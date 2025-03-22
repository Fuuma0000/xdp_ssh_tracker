package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// sshConnGaugeはリモートIPごとのSSH接続開始イベントのカウントを保持します。
var sshConnGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "ssh_connection_count",
		Help: "Number of SSH connection start events by remote IP address.",
	},
	[]string{"remote_ip"},
)

func init() {
	prometheus.MustRegister(sshConnGauge)
}

func main() {
	// ピンされたBPFマップを読み込みます
	bpfMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ssh_ip_count", nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
	}
	defer bpfMap.Close()

	// 定期的にBPFマップを読み出してPrometheusメトリクスを更新するゴルーチン
	go func() {
		for {
			// 古い値をリセット
			sshConnGauge.Reset()

			var key uint32
			var value uint64
			iterator := bpfMap.Iterate()
			for iterator.Next(&key, &value) {
				// ネットワークバイトオーダーのIPアドレスを変換して文字列化
				ip := net.IPv4(byte(key), byte(key>>8), byte(key>>16), byte(key>>24))
				sshConnGauge.WithLabelValues(ip.String()).Set(float64(value))
			}
			if err := iterator.Err(); err != nil {
				log.Printf("error iterating map: %v", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// HTTPハンドラーを設定し、Prometheusのエクスポートエンドポイントを提供します。
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Exporter is listening on :9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}
