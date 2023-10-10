/**
 * @name linux-998912346c0da53a6dbb71fab3a138586b596b30-ov518_mode_init_regs
 * @id cpp/linux/998912346c0da53a6dbb71fab3a138586b596b30/ov518-mode-init-regs
 * @description linux-998912346c0da53a6dbb71fab3a138586b596b30-ov518_mode_init_regs NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valt_3595, Parameter vsd_3591, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_3595
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="usb_err"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="gspca_dev"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsd_3591
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_2(Function func) {
	exists(ReturnStmt target_2 |
		target_2.toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_2))
}

predicate func_4(Variable vgspca_dev_3593, Variable valt_3595, Parameter vsd_3591) {
	exists(NotExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=valt_3595
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3%s: Couldn't get altsetting\n"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="v4l2_dev"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgspca_dev_3593
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="usb_err"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="gspca_dev"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsd_3591
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).toString() = "return ...")
}

predicate func_5(Parameter vsd_3591) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="gspca_dev"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsd_3591)
}

from Function func, Variable vgspca_dev_3593, Variable valt_3595, Parameter vsd_3591
where
not func_0(valt_3595, vsd_3591, func)
and not func_2(func)
and valt_3595.getType().hasName("usb_host_interface *")
and func_4(vgspca_dev_3593, valt_3595, vsd_3591)
and vsd_3591.getType().hasName("sd *")
and func_5(vsd_3591)
and vgspca_dev_3593.getParentScope+() = func
and valt_3595.getParentScope+() = func
and vsd_3591.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
