import { useState, useEffect } from "react";
import api from "../api/apiClient";

export function useAPI(url) {

    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {

        if (!url) return;

        async function fetchData() {

            try {

                setLoading(true);

                const response = await api.get(url);

                setData(response.data);

            } catch (err) {

                console.error(err);

                setError(err);

            } finally {

                setLoading(false);

            }

        }

        fetchData();

    }, [url]);

    return {

        data,
        loading,
        error

    };

}
