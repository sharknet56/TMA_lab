import os
import glob
import time
import numpy as np
from scapy.all import rdpcap
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, Dropout
from tensorflow.keras.utils import to_categorical

# --- CONFIGURACIÓN GLOBAL ---
CANTIDAD_META = 1000000    # Objetivo: 100k muestras (Igual que pondremos en Flows)
MAX_LEN = 500             # Subimos de 50 a 500 (50 es muy poco, pierdes info útil)
DATA_FRAC = 1.0           # Nos quedamos todo lo que leamos
# Cálculo: 100.000 / 27 dispositivos = ~3700. Ponemos 4000 para ir sobrados.
MAX_PKTS_PER_FILE = 100000

def pcap_to_matrix(file_path, max_len=MAX_LEN, data_frac=DATA_FRAC, max_pkts_read=MAX_PKTS_PER_FILE):
    """
    Lee un PCAP, convierte los paquetes a matrices numéricas y 
    devuelve solo una muestra aleatoria (data_frac) para ahorrar memoria.
    """
    try:
        # 1. Leer los paquetes (limitado por max_pkts_read para no leer archivos gigantes enteros)
        packets = rdpcap(file_path, count=max_pkts_read)
        
        raw_data = []
        
        # 2. Convertir cada paquete a lista de números
        for pkt in packets:
            # Obtener bytes crudos
            byte_list = list(bytes(pkt))
            
            # Recortar o Rellenar (Padding) para tener tamaño fijo
            if len(byte_list) > max_len:
                byte_list = byte_list[:max_len] # Recortar si sobra
            else:
                byte_list = byte_list + [0] * (max_len - len(byte_list)) # Rellenar con ceros si falta
                
            raw_data.append(byte_list)
            
        # Convertimos a array de Numpy temporalmente
        data_array = np.array(raw_data)
        
        # Si el archivo estaba vacío o no se leyó nada, devolvemos array vacío
        if len(data_array) == 0:
            return np.array([])

        # 3. MUESTREO ALEATORIO (Aquí aplicamos el 20% o lo que definas)
        # Calculamos cuántos paquetes nos quedamos
        n_keep = int(len(data_array) * data_frac)
        
        if n_keep > 0:
            # Elegimos índices aleatorios sin repetir
            indices = np.random.choice(len(data_array), n_keep, replace=False)
            # Devolvemos solo los paquetes seleccionados
            return data_array[indices]
        else:
            # Si el porcentaje es muy bajo y da 0 paquetes, devolvemos vacío
            return np.array([])

    except Exception as e:
        print(f"Error leyendo {file_path}: {e}")
        return np.array([])
def ejecutar_modelo_pcaps(ruta_datos='data_pcaps/*.pcap'):
    print(f"\n--- [PAQUETES/DL] Iniciando carga (Meta: {CANTIDAD_META} muestras) ---")
    
    files = glob.glob(ruta_datos)
    X_list, y_list = [], []
    
    print("Procesando PCAPs...")
    for f in files:
        label = os.path.basename(f).split('.')[0]
        # Usamos las variables globales MAX_LEN, DATA_FRAC, MAX_PKTS_PER_FILE
        data = pcap_to_matrix(f)
        if len(data) > 0:
            X_list.append(data)
            y_list.extend([label] * len(data))
            
    if not X_list: return 0, 0

    X = np.concatenate(X_list)
    # Convertimos y_list a array para poder indexarlo
    y_labels = np.array(y_list) 

    # --- RECORTE EXACTO PARA IGUALDAD DE CONDICIONES ---
    if len(X) > CANTIDAD_META:
        print(f"Recortando de {len(X)} a {CANTIDAD_META} para igualar con Flows...")
        # Elegimos índices aleatorios para mantener la variedad de clases
        indices = np.random.choice(len(X), CANTIDAD_META, replace=False)
        X = X[indices]
        y_labels = y_labels[indices]
    # ---------------------------------------------------

    # Normalizar bytes
    X = X / 255.0 
    
    # Codificar etiquetas
    le = LabelEncoder()
    y_integers = le.fit_transform(y_labels)
    y_onehot = to_categorical(y_integers)
    
    # Reshape para CNN
    X = X.reshape(X.shape[0], X.shape[1], 1)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y_onehot, test_size=0.3, random_state=42)

    # Modelo
    model = Sequential([
        Conv1D(32, 3, activation='relu', input_shape=(MAX_LEN, 1)),
        MaxPooling1D(2),
        Flatten(),
        Dense(64, activation='relu'),
        Dropout(0.5),
        Dense(len(le.classes_), activation='softmax')
    ])
    
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    print(f"Entrenando CNN con {len(X_train)} muestras...")
    start_time = time.time()
    
    # Epochs: 5 es un buen número para empezar. Si va rápido, sube a 10.
    model.fit(X_train, y_train, epochs=5, batch_size=32, verbose=1)
    
    tiempo_total = time.time() - start_time
    
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"--> [PAQUETES] Terminado. Tiempo: {tiempo_total:.2f}s | Accuracy: {acc:.4f}")
    return acc, tiempo_total