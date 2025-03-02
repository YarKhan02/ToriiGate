package suspiciousSites

import (
    "bufio"
    "net/http"
)

func FetchSuspiciousSites(url string) ([]string, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var sites []string
    scanner := bufio.NewScanner(resp.Body)
    for scanner.Scan() {
        sites = append(sites, scanner.Text())
    }
    return sites, scanner.Err()
}