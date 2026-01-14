import matplotlib.pyplot as plt
import script_flows
import script_pcaps

def main():
    print("=== PROYECTO MONITORIZACIÓN IOT: FLOWS vs PAQUETES ===")
    
    # 1. Ejecutar Flows
    acc_flow, time_flow = script_flows.ejecutar_modelo_flows()
    
    # 2. Ejecutar Paquetes
    acc_pcap, time_pcap = script_pcaps.ejecutar_modelo_pcaps()
    
    if time_flow == 0 and time_pcap == 0:
        print("No se generaron datos. Revisa las carpetas.")
        return

    # 3. Graficar
    labels = ['Flows (ML)', 'Paquetes (DL)']
    accuracies = [acc_flow, acc_pcap]
    times = [time_flow, time_pcap]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Gráfica Accuracy
    ax1.bar(labels, accuracies, color=['#4CAF50', '#2196F3'])
    ax1.set_title('Comparación de Precisión (Accuracy)')
    ax1.set_ylim(0, 1.1)
    for i, v in enumerate(accuracies):
        ax1.text(i, v + 0.02, f"{v*100:.1f}%", ha='center', fontweight='bold')

    # Gráfica Tiempo
    ax2.bar(labels, times, color=['#4CAF50', '#2196F3'])
    ax2.set_title('Tiempo de Entrenamiento (Segundos)')
    ax2.set_ylabel('Segundos')
    for i, v in enumerate(times):
        ax2.text(i, v, f"{v:.1f}s", ha='center', va='bottom', fontweight='bold')

    plt.suptitle('Análisis de Tráfico IoT: Flows vs Paquetes')
    plt.tight_layout()
    plt.savefig('comparativa_resultados.png')
    plt.show()
    
    print("\nGráfica guardada como 'comparativa_resultados.png'")

if __name__ == "__main__":
    main()