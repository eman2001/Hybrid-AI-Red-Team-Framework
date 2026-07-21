import { Menu, Moon, Sun, ShieldCheck } from "lucide-react";
import { useState } from "react";


function Navbar({ toggleSidebar }) {


const [dark, setDark] = useState(
    localStorage.getItem("theme") === "dark"
);



const toggleDark = ()=>{


    const mode = !dark;


    setDark(mode);



    if(mode){


        document.documentElement.classList.add("dark");


        localStorage.setItem(
            "theme",
            "dark"
        );


    }else{


        document.documentElement.classList.remove("dark");


        localStorage.setItem(
            "theme",
            "light"
        );


    }


};




return (

<header className="navbar">



<button
className="menu-btn"
onClick={toggleSidebar}
>

<Menu size={22}/>

</button>





<div className="navbar-brand">



<div className="navbar-logo">

<ShieldCheck size={24}/>

</div>





<div>

<h3>
Hybrid AI Red Team
</h3>


<span>
Security Operations Center
</span>


</div>



</div>







<div className="navbar-actions">



<div className="online">

<span className="dot"></span>

System Online

</div>






<button
className="theme-btn"
onClick={toggleDark}
title="Toggle Dark Mode"
>

{

dark ?

<Sun size={20}/>

:

<Moon size={20}/>

}


</button>




</div>



</header>

)

}



export default Navbar;
