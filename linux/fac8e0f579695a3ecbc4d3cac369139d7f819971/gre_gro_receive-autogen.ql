/**
 * @name linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-gre_gro_receive
 * @id cpp/linux/fac8e0f579695a3ecbc4d3cac369139d7f819971/gre_gro_receive
 * @description linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-gre_gro_receive 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_118, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="encap_mark"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cb"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_118
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vskb_118, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="encap_mark"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cb"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_118
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

from Function func, Parameter vskb_118
where
not func_0(vskb_118, func)
and not func_1(vskb_118, func)
and vskb_118.getType().hasName("sk_buff *")
and vskb_118.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
