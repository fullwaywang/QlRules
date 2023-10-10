/**
 * @name linux-bd23a7269834dc7c1f93e83535d16ebc44b75eba-vbg_misc_device_ioctl
 * @id cpp/linux/bd23a7269834dc7c1f93e83535d16ebc44b75eba/vbg_misc_device_ioctl
 * @description linux-bd23a7269834dc7c1f93e83535d16ebc44b75eba-vbg_misc_device_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vhdr_89, Variable vbuf_92, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuf_92
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vhdr_89
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_4(Variable vhdr_89) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="size_in"
		and target_4.getQualifier().(VariableAccess).getTarget()=vhdr_89)
}

predicate func_7(Variable vhdr_89) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="size_out"
		and target_7.getQualifier().(VariableAccess).getTarget()=vhdr_89)
}

predicate func_8(Variable vbuf_92) {
	exists(NotExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vbuf_92
		and target_8.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_8.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12")
}

from Function func, Parameter varg_85, Variable vhdr_89, Variable vret_91, Variable vbuf_92
where
not func_0(vhdr_89, vbuf_92, func)
and func_4(vhdr_89)
and varg_85.getType().hasName("unsigned long")
and vhdr_89.getType().hasName("vbg_ioctl_hdr")
and func_7(vhdr_89)
and vret_91.getType().hasName("int")
and vbuf_92.getType().hasName("void *")
and func_8(vbuf_92)
and varg_85.getParentScope+() = func
and vhdr_89.getParentScope+() = func
and vret_91.getParentScope+() = func
and vbuf_92.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
