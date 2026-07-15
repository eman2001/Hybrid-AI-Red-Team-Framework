import {useState} from "react";
import {runScan as apiRunScan} from "../api/apiClient";


export function useScan(){

const [loading,setLoading]=useState(false);


async function runScan(target,lhost){

try{

setLoading(true);

const result = await apiRunScan(
    target,
    lhost
);

return result;


}
finally{

setLoading(false);

}

}


return {

runScan,
loading

};

}
