#!/usr/bin/env python3
"""
Script de prueba para verificar la carga del modelo y encoder
"""
import joblib
import sys

def test_loading():
    print(" Probando carga de archivos del modelo...")
    print()
    
    try:
        # Cargar modelo
        print(" Cargando model.pkl...")
        model = joblib.load('model.pkl')
        print(f"   ✓ Modelo cargado: {type(model).__name__}")
        print(f"   ✓ Features: {model.n_features_in_}")
        print(f"   ✓ Clases: {model.n_classes_}")
        print()
        
        # Cargar encoder
        print("  Cargando encoder.pkl...")
        encoder = joblib.load('encoder.pkl')
        print(f"   ✓ Encoder cargado: {type(encoder).__name__}")
        print(f"   ✓ Categorías: {list(encoder.classes_)}")
        print()
        
        # Verificar compatibilidad
        print(" Verificación de compatibilidad:")
        if hasattr(model, 'classes_'):
            if len(model.classes_) == len(encoder.classes_):
                print(f"   ✓ Número de clases coincide: {len(encoder.classes_)}")
            else:
                print(f"   ⚠ Mismatch: modelo tiene {len(model.classes_)} clases, encoder tiene {len(encoder.classes_)}")
        
        print()
        print(" Categorías disponibles:")
        for i, cat in enumerate(encoder.classes_, 1):
            print(f"   {i}. {cat}")
        
        print()
        print(" Todo OK - Los archivos se cargaron correctamente")
        return True
        
    except FileNotFoundError as e:
        print(f" Error: Archivo no encontrado - {e}")
        return False
    except Exception as e:
        print(f" Error al cargar: {e}")
        return False

if __name__ == '__main__':
    success = test_loading()
    sys.exit(0 if success else 1)
