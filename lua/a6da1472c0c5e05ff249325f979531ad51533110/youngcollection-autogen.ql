/**
 * @name lua-a6da1472c0c5e05ff249325f979531ad51533110-youngcollection
 * @id cpp/lua/a6da1472c0c5e05ff249325f979531ad51533110/youngcollection
 * @description lua-a6da1472c0c5e05ff249325f979531ad51533110-lgc.c-youngcollection CVE-2020-24371
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vg_1138, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcstate"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1138
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vg_1138, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("markold")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_1138
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="finobj"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1138
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="finobjrold"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1138
}

predicate func_2(Parameter vg_1138, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("GCObject **")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sweepgen")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_1138
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="allgc"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1138
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="survival"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1138
}

from Function func, Parameter vg_1138, ExprStmt target_1, ExprStmt target_2
where
not func_0(vg_1138, target_1, target_2, func)
and func_1(vg_1138, target_1)
and func_2(vg_1138, target_2)
and vg_1138.getType().hasName("global_State *")
and vg_1138.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
