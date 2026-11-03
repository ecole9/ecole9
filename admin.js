// بيانات تجريبية داخل ذاكرة الصفحة فقط؛ ليست نظام حسابات حقيقياً.
const form=document.getElementById('accountForm');
const rows=document.getElementById('accountRows');
const roleNames={teacher:'أستاذ',parent:'ولي',staff:'موظف إداري'};
let accounts=[];
function render(){
 document.getElementById('totalCount').textContent=accounts.length;
 document.getElementById('teacherCount').textContent=accounts.filter(a=>a.role==='teacher').length;
 document.getElementById('parentCount').textContent=accounts.filter(a=>a.role==='parent').length;
 document.getElementById('staffCount').textContent=accounts.filter(a=>a.role==='staff').length;
 rows.replaceChildren();
 if(!accounts.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.className='empty';td.textContent='لا توجد حسابات تجريبية بعد.';tr.append(td);rows.append(tr);return;}
 accounts.forEach((a,i)=>{const tr=document.createElement('tr');[a.name,a.email,roleNames[a.role]].forEach(value=>{const td=document.createElement('td');td.textContent=value;tr.append(td);});const td=document.createElement('td');const btn=document.createElement('button');btn.type='button';btn.className='delete';btn.textContent='حذف';btn.addEventListener('click',()=>{accounts.splice(i,1);render();});td.append(btn);tr.append(td);rows.append(tr);});
}
form.addEventListener('submit',event=>{event.preventDefault();const name=document.getElementById('fullName').value.trim();const email=document.getElementById('email').value.trim();const role=document.getElementById('role').value;if(!name||!email)return;if(accounts.some(a=>a.email.toLowerCase()===email.toLowerCase())){alert('هذا البريد موجود بالفعل في القائمة التجريبية.');return;}accounts.push({name,email,role});form.reset();render();});
render();