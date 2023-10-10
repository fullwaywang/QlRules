/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_transport_read
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-transport-read
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/transport.c-_libssh2_transport_read CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_276, RelationalOperation target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="40000"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_2, Function func, ReturnStmt target_1) {
		target_1.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vp_276, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_2.getGreaterOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vp_276, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="padding_length"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
}

from Function func, Variable vp_276, ReturnStmt target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(vp_276, target_2, target_3)
and func_1(target_2, func, target_1)
and func_2(vp_276, target_2)
and func_3(vp_276, target_3)
and vp_276.getType().hasName("transportpacket *")
and vp_276.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
