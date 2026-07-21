import {
  Search,
  Shield,
  Target,
  FileText,
  Activity,
  AlertTriangle
} from "lucide-react";


function ActivityFeed({ activities = [] }) {


const icons = {

search:<Search size={22}/>,

scan:<Search size={22}/>,

shield:<Shield size={22}/>,

target:<Target size={22}/>,

file:<FileText size={22}/>,

activity:<Activity size={22}/>,

alert:<AlertTriangle size={22}/>

};



return (
<div className="panel">


<h2>
📡 Live Activity Feed
</h2>


<div className="activity-feed">


{
activities.length === 0 ? (

<div className="activity-empty">
No recent activity
</div>

)

:

(

activities.map((item,index)=>(


<div 
className="activity-item"
key={index}
>


<div className={`activity-icon ${item.type}`}>

{
icons[item.icon] || <Activity size={22}/>
}

</div>



<div className="activity-content">


<h4>
{item.title}
</h4>


<p>
{item.description}
</p>


<span>
{item.time}
</span>


</div>


</div>


))

)

}


</div>


</div>
);


}


export default ActivityFeed;
