/**
 * @name lua-a6da1472c0c5e05ff249325f979531ad51533110-luaC_barrier_
 * @id cpp/lua/a6da1472c0c5e05ff249325f979531ad51533110/luaC-barrier-
 * @description lua-a6da1472c0c5e05ff249325f979531ad51533110-lgc.c-luaC_barrier_ CVE-2020-24371
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vg_194, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="gckind"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_194
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vo_193, Variable vg_194, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="marked"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_193
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="marked"
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_193
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-64"
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="currentwhite"
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_194
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="24"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vg_194, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="gcstate"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_194
		and target_2.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_3(Variable vg_194, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("reallymarkobject")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_194
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("GCObject *")
}

from Function func, Parameter vo_193, Variable vg_194, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(vg_194, target_2, target_3, target_1)
and func_1(vo_193, vg_194, target_2, target_1)
and func_2(vg_194, target_2)
and func_3(vg_194, target_3)
and vo_193.getType().hasName("GCObject *")
and vg_194.getType().hasName("global_State *")
and vo_193.getFunction() = func
and vg_194.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
