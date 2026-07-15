import { useState, useEffect } from "react";
import api from "../api/apiClient";

export function useDashboard(url) {

    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {

        let mounted = true;

        async function load() {

            try {

                setLoading(true);

                const response = await api.get(url);

                if (mounted) {
                    setData(response.data);
                }

            } catch (err) {

                console.error(err);

                if (mounted) {
                    setError(err);
                }

            } finally {

                if (mounted) {
                    setLoading(false);
                }

            }

        }

        load();

        return () => {
            mounted = false;
        };

    }, [url]);

    return {
        data,
        loading,
        error,
    };

}
