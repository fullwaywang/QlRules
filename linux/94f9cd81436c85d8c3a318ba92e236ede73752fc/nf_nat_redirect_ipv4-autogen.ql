/**
 * @name linux-94f9cd81436c85d8c3a318ba92e236ede73752fc-nf_nat_redirect_ipv4
 * @id cpp/linux/94f9cd81436c85d8c3a318ba92e236ede73752fc/nf_nat_redirect_ipv4
 * @description linux-94f9cd81436c85d8c3a318ba92e236ede73752fc-nf_nat_redirect_ipv4 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnewdst_38, Variable vindev_51, Variable vifa_52) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vindev_51
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="ifa_list"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindev_51
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vifa_52
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ifa_list"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindev_51
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewdst_38
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ifa_local"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vifa_52)
}

predicate func_2(Variable vnewdst_38, Variable vindev_51, Variable vifa_52) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vindev_51
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vifa_52
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ifa_list"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindev_51
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewdst_38
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ifa_local"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vifa_52)
}

predicate func_3(Variable vindev_51, Parameter vskb_32) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vindev_51
		and target_3.getRValue().(FunctionCall).getTarget().hasName("__in_dev_get_rcu")
		and target_3.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_3.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_32)
}

from Function func, Variable vnewdst_38, Variable vindev_51, Variable vifa_52, Parameter vskb_32
where
not func_0(vnewdst_38, vindev_51, vifa_52)
and func_2(vnewdst_38, vindev_51, vifa_52)
and vnewdst_38.getType().hasName("__be32")
and vindev_51.getType().hasName("in_device *")
and func_3(vindev_51, vskb_32)
and vifa_52.getType().hasName("in_ifaddr *")
and vskb_32.getType().hasName("sk_buff *")
and vnewdst_38.getParentScope+() = func
and vindev_51.getParentScope+() = func
and vifa_52.getParentScope+() = func
and vskb_32.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
