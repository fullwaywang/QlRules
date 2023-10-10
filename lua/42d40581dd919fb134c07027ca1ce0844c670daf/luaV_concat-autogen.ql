/**
 * @name lua-42d40581dd919fb134c07027ca1ce0844c670daf-luaV_concat
 * @id cpp/lua/42d40581dd919fb134c07027ca1ce0844c670daf/luaV-concat
 * @description lua-42d40581dd919fb134c07027ca1ce0844c670daf-lvm.c-luaV_concat CVE-2022-33099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtotal_638, Variable vtop_642, Parameter vL_638, FunctionCall target_6, LogicalAndExpr target_7, ExprStmt target_8, PointerArithmeticOperation target_9, ExprStmt target_10) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="top"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_638
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vtop_642
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vtotal_638
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_9.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtop_642, Parameter vL_638, PointerArithmeticOperation target_11, ExprStmt target_12) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="top"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_638
		and target_1.getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vtop_642
		and target_1.getRValue().(PointerArithmeticOperation).getRightOperand() instanceof SubExpr
		and target_11.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(CommaExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vL_638, FunctionCall target_6, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("luaG_runerror")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_638
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="string length overflow"
		and target_2.getParent().(IfStmt).getCondition()=target_6
}

predicate func_3(Parameter vL_638, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="top"
		and target_3.getQualifier().(VariableAccess).getTarget()=vL_638
}

predicate func_4(Variable vn_643, SubExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vn_643
		and target_4.getRightOperand().(Literal).getValue()="1"
}

predicate func_5(Parameter vL_638, AssignPointerSubExpr target_5) {
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="top"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_638
		and target_5.getRValue() instanceof SubExpr
}

predicate func_6(FunctionCall target_6) {
		target_6.getTarget().hasName("__builtin_expect")
		and target_6.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_6.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(DivExpr).getValue()="9223372036854775807"
		and target_6.getArgument(0).(EqualityOperation).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_6.getArgument(0).(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getArgument(1).(Literal).getValue()="0"
}

predicate func_7(Parameter vtotal_638, Variable vn_643, Parameter vL_638, LogicalAndExpr target_7) {
		target_7.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vn_643
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtotal_638
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tt_"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="15"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tt_"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="15"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("luaO_tostring")
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_638
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(CommaExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_8(Parameter vtotal_638, Variable vn_643, ExprStmt target_8) {
		target_8.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vtotal_638
		and target_8.getExpr().(AssignSubExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_643
		and target_8.getExpr().(AssignSubExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_9(Variable vtop_642, Variable vn_643, PointerArithmeticOperation target_9) {
		target_9.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vtop_642
		and target_9.getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vn_643
		and target_9.getRightOperand().(Literal).getValue()="1"
}

predicate func_10(Variable vtop_642, Variable vn_643, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("copy2buff")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtop_642
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vn_643
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("char[40]")
}

predicate func_11(Variable vtop_642, Variable vn_643, PointerArithmeticOperation target_11) {
		target_11.getLeftOperand().(VariableAccess).getTarget()=vtop_642
		and target_11.getRightOperand().(VariableAccess).getTarget()=vn_643
}

predicate func_12(Parameter vL_638, ExprStmt target_12) {
		target_12.getExpr().(CommaExpr).getLeftOperand().(VariableAccess).getTarget()=vL_638
		and target_12.getExpr().(CommaExpr).getRightOperand().(Literal).getValue()="0"
}

from Function func, Parameter vtotal_638, Variable vtop_642, Variable vn_643, Parameter vL_638, ExprStmt target_2, PointerFieldAccess target_3, SubExpr target_4, AssignPointerSubExpr target_5, FunctionCall target_6, LogicalAndExpr target_7, ExprStmt target_8, PointerArithmeticOperation target_9, ExprStmt target_10, PointerArithmeticOperation target_11, ExprStmt target_12
where
not func_0(vtotal_638, vtop_642, vL_638, target_6, target_7, target_8, target_9, target_10)
and not func_1(vtop_642, vL_638, target_11, target_12)
and func_2(vL_638, target_6, target_2)
and func_3(vL_638, target_3)
and func_4(vn_643, target_4)
and func_5(vL_638, target_5)
and func_6(target_6)
and func_7(vtotal_638, vn_643, vL_638, target_7)
and func_8(vtotal_638, vn_643, target_8)
and func_9(vtop_642, vn_643, target_9)
and func_10(vtop_642, vn_643, target_10)
and func_11(vtop_642, vn_643, target_11)
and func_12(vL_638, target_12)
and vtotal_638.getType().hasName("int")
and vtop_642.getType().hasName("StkId")
and vn_643.getType().hasName("int")
and vL_638.getType().hasName("lua_State *")
and vtotal_638.getFunction() = func
and vtop_642.(LocalVariable).getFunction() = func
and vn_643.(LocalVariable).getFunction() = func
and vL_638.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
