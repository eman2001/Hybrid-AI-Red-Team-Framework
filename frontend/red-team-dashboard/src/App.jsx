import { useEffect, useState } from "react";
import AppRoutes from "./routes/AppRoutes";


function App(){

const [dark,setDark]=useState(
    localStorage.getItem("theme")==="dark"
);


useEffect(()=>{

if(dark){

document.body.classList.add("dark");

localStorage.setItem("theme","dark");

}
else{

document.body.classList.remove("dark");

localStorage.setItem("theme","light");

}


},[dark]);



return (

<AppRoutes 
dark={dark}
setDark={setDark}
/>

)

}


export default App;
