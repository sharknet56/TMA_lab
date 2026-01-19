import os
import glob
import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

DATA_FRAC = 1  # Usar el X% del dataset. Numero entre 0 y 1.
CANTIDAD_META = 1000000  # LA MISMA CIFRA QUE EN PCAPS

def ejecutar_modelo_flows(ruta_datos='data_flows/*.csv'):
    print("\n--- [FLOWS] Iniciando carga y entrenamiento ---")
    
    # 1. Cargar CSVs (Basado en tu script original)
    file_paths = glob.glob(ruta_datos)
    if not file_paths:
        print("Error: No se encontraron CSVs en", ruta_datos)
        return 0, 0

    df_list = []
    for fp in file_paths:
        # Leemos todo como texto al principio o especificamos low_memory=False para evitar el warning
        df = pd.read_csv(fp, low_memory=False)
        # Asumimos que el nombre del archivo es la clase (ej: 'AmazonEcho.csv')
        device_name = os.path.basename(fp).split('.')[0] 
        df['device'] = device_name
        df_list.append(df)


    df_all = pd.concat(df_list, ignore_index=True)

    
    # MUESTREO POR CANTIDAD FIJA
    
    if len(df_all) > CANTIDAD_META:
        print(f"Recortando Flows de {len(df_all)} a {CANTIDAD_META}...")
        df_all = df_all.sample(n=CANTIDAD_META, random_state=42)
    
    """
    # MUESTREO POR PORCENTAJE
    if DATA_FRAC < 1.0:
        print(f"Dataset original: {len(df_all)} flows. Usando el {DATA_FRAC*100}%...")
        # frac=0.2 nos da un 20% aleatorio
        df_all = df_all.sample(frac=DATA_FRAC, random_state=42) 
    """
    print(f"Entrenando con {len(df_all)} flows finales.")
    print(f"Cargados {len(df_all)} flows de {df_all['device'].nunique()} dispositivos.")

    # 2. Limpieza (Usando las columnas que tu script sugería borrar)
    drop_cols = ['time','srcMac','dstMac','ethType','srcIp','dstIp','ipProto','srcPort','dstPort','flowSeqNum']
    # Nota: Si da error porque falta alguna columna, quítala de esta lista
    # Remover las columnas descartadas + la etiqueta para evitar fuga de información
    cols_to_drop = [c for c in drop_cols if c in df_all.columns]
    if 'device' in df_all.columns:
        cols_to_drop.append('device')
    X = df_all.drop(columns=cols_to_drop)
    y = df_all['device']

    # 3. Pipeline (Preprocesamiento + Modelo)
    cat_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    num_cols = X.select_dtypes(include=['number']).columns.tolist()

    preprocessor = ColumnTransformer(transformers=[
        ('ohe', OneHotEncoder(drop='first', handle_unknown='ignore'), cat_cols),
        ('scale', StandardScaler(), num_cols)
    ])

    # Usamos parámetros fijos (sin GridSearch) para medir tiempo de un solo entrenamiento
    pipeline = Pipeline([
        ('preproc', preprocessor),
        ('rf', RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42))
    ])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

    # 4. Entrenar y Medir Tiempo
    print("Entrenando Random Forest...")
    start_time = time.time()
    pipeline.fit(X_train, y_train)
    tiempo_total = time.time() - start_time

    # 5. Evaluar
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"--> [FLOWS] Terminado. Tiempo: {tiempo_total:.2f}s | Accuracy: {acc:.4f}")
    return acc, tiempo_total