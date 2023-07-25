/**
 * @name lua-cf613cdc6fa367257fc61c256f63d917350858b5-luaD_pretailcall
 * @id cpp/lua/cf613cdc6fa367257fc61c256f63d917350858b5/luaD-pretailcall
 * @description lua-cf613cdc6fa367257fc61c256f63d917350858b5-ldo.c-luaD_pretailcall CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdelta_521, Variable vfsize_530, ExprStmt target_6) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vfsize_530
		and target_0.getRightOperand().(VariableAccess).getTarget()=vdelta_521
		and target_0.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfsize_530
		and target_0.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getExpr().(AssignPointerSubExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vL_520, Parameter vdelta_521, Variable vfsize_530, EqualityOperation target_7, ExprStmt target_8) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vfsize_530
		and target_1.getRightOperand().(VariableAccess).getTarget()=vdelta_521
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("luaD_growstack")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_520
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfsize_530
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vL_520, Parameter vfunc_520, FunctionCall target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfunc_520
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="stack"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("ptrdiff_t")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(FunctionCall target_9, Function func, ExprStmt target_3) {
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vfsize_530, VariableAccess target_4) {
		target_4.getTarget()=vfsize_530
		and target_4.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_4.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(LEExpr).getParent().(NEExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Parameter vL_520, Variable vfsize_530, VariableAccess target_5) {
		target_5.getTarget()=vfsize_530
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("luaD_growstack")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_520
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_6(Parameter vdelta_521, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="func"
		and target_6.getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CallInfo *")
		and target_6.getExpr().(AssignPointerSubExpr).getRValue().(VariableAccess).getTarget()=vdelta_521
}

predicate func_7(Parameter vL_520, Variable vfsize_530, EqualityOperation target_7) {
		target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="stack_last"
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfsize_530
		and target_7.getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Parameter vfunc_520, Variable vfsize_530, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="top"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("CallInfo *")
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfunc_520
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfsize_530
}

predicate func_9(Parameter vL_520, Variable vfsize_530, FunctionCall target_9) {
		target_9.getTarget().hasName("__builtin_expect")
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="stack_last"
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfsize_530
		and target_9.getArgument(0).(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getArgument(1).(Literal).getValue()="0"
}

predicate func_10(Parameter vL_520, Variable vfsize_530, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("luaD_growstack")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_520
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfsize_530
		and target_10.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_11(Parameter vL_520, Parameter vfunc_520, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="top"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_520
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfunc_520
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vL_520, Parameter vfunc_520, Parameter vdelta_521, Variable vfsize_530, ExprStmt target_3, VariableAccess target_4, VariableAccess target_5, ExprStmt target_6, EqualityOperation target_7, ExprStmt target_8, FunctionCall target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(vdelta_521, vfsize_530, target_6)
and not func_1(vL_520, vdelta_521, vfsize_530, target_7, target_8)
and not func_2(vL_520, vfunc_520, target_9, target_10, target_11)
and func_3(target_9, func, target_3)
and func_4(vfsize_530, target_4)
and func_5(vL_520, vfsize_530, target_5)
and func_6(vdelta_521, target_6)
and func_7(vL_520, vfsize_530, target_7)
and func_8(vfunc_520, vfsize_530, target_8)
and func_9(vL_520, vfsize_530, target_9)
and func_10(vL_520, vfsize_530, target_10)
and func_11(vL_520, vfunc_520, target_11)
and vL_520.getType().hasName("lua_State *")
and vfunc_520.getType().hasName("StkId")
and vdelta_521.getType().hasName("int")
and vfsize_530.getType().hasName("int")
and vL_520.getFunction() = func
and vfunc_520.getFunction() = func
and vdelta_521.getFunction() = func
and vfsize_530.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
