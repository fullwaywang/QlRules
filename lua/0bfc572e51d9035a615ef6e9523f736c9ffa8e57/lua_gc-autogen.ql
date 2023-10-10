/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lua_gc
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/lua-gc
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lapi.c-lua_gc CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vg_1139, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="gcrunning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vg_1139
}

*/
predicate func_1(Variable vg_1139, ExprStmt target_14, ExprStmt target_15, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_2(Variable vg_1139, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="gcrunning"
		and target_2.getQualifier().(VariableAccess).getTarget()=vg_1139
}

*/
predicate func_3(Variable vg_1139, ExprStmt target_15, ExprStmt target_16, Literal target_3) {
		target_3.getValue()="1"
		and not target_3.getValue()="0"
		and target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Variable vg_1139, Initializer target_4) {
		target_4.getExpr().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
}

/*predicate func_5(Variable vg_1139, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="gcrunning"
		and target_5.getQualifier().(VariableAccess).getTarget()=vg_1139
}

*/
predicate func_6(Variable vg_1139, ExprStmt target_17, Literal target_6) {
		target_6.getValue()="1"
		and not target_6.getValue()="0"
		and target_6.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_6.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_6.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_7(Variable vg_1139, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="gcrunning"
		and target_7.getQualifier().(VariableAccess).getTarget()=vg_1139
}

*/
predicate func_8(Variable vg_1139, Variable voldrunning_1169, VariableAccess target_8) {
		target_8.getTarget()=voldrunning_1169
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
}

predicate func_9(Variable vg_1139, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="gcrunning"
		and target_9.getQualifier().(VariableAccess).getTarget()=vg_1139
}

predicate func_10(Parameter vL_1136, ExprStmt target_18) {
	exists(Initializer target_10 |
		target_10.getExpr().(PointerFieldAccess).getTarget().getName()="l_G"
		and target_10.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_1136
		and target_10.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_11(Variable vg_1139, ExprStmt target_19, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_11.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_11.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_11.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_11)
		and target_11.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Variable vg_1139, ExprStmt target_20, ExprStmt target_21) {
	exists(EqualityOperation target_12 |
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_12.getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vL_1136, Variable vg_1139, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="l_G"
		and target_13.getQualifier().(VariableAccess).getTarget()=vL_1136
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_1139
}

predicate func_14(Parameter vL_1136, Variable vg_1139, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_1139
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l_G"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_1136
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable vg_1139, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("luaE_setdebt")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_1139
		and target_15.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_16(Variable vg_1139, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="totalbytes"
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="GCdebt"
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_16.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="10"
}

predicate func_17(Variable vg_1139, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("luaE_setdebt")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vg_1139
		and target_17.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_18(Parameter vL_1136, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("luaC_fullgc")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_1136
		and target_18.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_19(Variable vg_1139, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="gckind"
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="lastatomic"
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="10"
		and target_19.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="11"
}

predicate func_20(Variable vg_1139, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcstepmul"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_21(Variable vg_1139, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_21.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_21.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1139
}

from Function func, Parameter vL_1136, Variable vg_1139, Variable voldrunning_1169, Literal target_1, Literal target_3, Initializer target_4, Literal target_6, VariableAccess target_8, PointerFieldAccess target_9, PointerFieldAccess target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21
where
func_1(vg_1139, target_14, target_15, target_1)
and func_3(vg_1139, target_15, target_16, target_3)
and func_4(vg_1139, target_4)
and func_6(vg_1139, target_17, target_6)
and func_8(vg_1139, voldrunning_1169, target_8)
and func_9(vg_1139, target_9)
and not func_10(vL_1136, target_18)
and not func_11(vg_1139, target_19, func)
and not func_12(vg_1139, target_20, target_21)
and func_13(vL_1136, vg_1139, target_13)
and func_14(vL_1136, vg_1139, func, target_14)
and func_15(vg_1139, target_15)
and func_16(vg_1139, target_16)
and func_17(vg_1139, target_17)
and func_18(vL_1136, target_18)
and func_19(vg_1139, target_19)
and func_20(vg_1139, target_20)
and func_21(vg_1139, target_21)
and vL_1136.getType().hasName("lua_State *")
and vg_1139.getType().hasName("global_State *")
and voldrunning_1169.getType().hasName("lu_byte")
and vL_1136.getFunction() = func
and vg_1139.(LocalVariable).getFunction() = func
and voldrunning_1169.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
