function Navbar({ toggleSidebar }) {

return (

<header className="navbar">

<button 
className="menu-btn"
onClick={toggleSidebar}
>
☰
</button>


<h3>
Security Operations Center
</h3>


<span className="online">
🟢 System Online
</span>


</header>

)

}

export default Navbar;
