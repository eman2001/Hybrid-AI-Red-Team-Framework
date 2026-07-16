import {Outlet} from "react-router-dom";
import {useState} from "react";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";


function MainLayout(){


const [open,setOpen]=useState(false);



return (

<div className="app-layout">


<Navbar 
toggleSidebar={()=>setOpen(true)}
/>



<Sidebar

open={open}

close={()=>setOpen(false)}

/>



<main className="content">

<Outlet/>

</main>



</div>

)

}


export default MainLayout;
