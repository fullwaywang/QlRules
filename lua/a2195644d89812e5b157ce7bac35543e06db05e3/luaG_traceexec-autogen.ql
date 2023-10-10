/**
 * @name lua-a2195644d89812e5b157ce7bac35543e06db05e3-luaG_traceexec
 * @id cpp/lua/a2195644d89812e5b157ce7bac35543e06db05e3/luaG-traceexec
 * @description lua-a2195644d89812e5b157ce7bac35543e06db05e3-ldebug.c-luaG_traceexec CVE-2020-15945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_822, LogicalOrExpr target_11, FunctionCall target_12) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="code"
		and target_0.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_822
		and target_0.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand() instanceof Literal
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vnpci_823, Parameter vL_798, FunctionCall target_12, ExprStmt target_13, EqualityOperation target_14) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_798
		and target_2.getRValue().(VariableAccess).getTarget()=vnpci_823
		and target_12.getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getRValue().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(BitwiseAndExpr target_15, Function func, DeclStmt target_3) {
		target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vp_822, Variable vnpci_823, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="code"
		and target_4.getQualifier().(VariableAccess).getTarget()=vp_822
		and target_4.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("changedline")
		and target_4.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_4.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof SubExpr
		and target_4.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnpci_823
}

predicate func_5(Parameter vL_798, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="oldpc"
		and target_5.getQualifier().(VariableAccess).getTarget()=vL_798
}

predicate func_6(Variable vp_822, Variable vnpci_823, Parameter vL_798, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="oldpc"
		and target_6.getQualifier().(VariableAccess).getTarget()=vL_798
		and target_6.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("changedline")
		and target_6.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_6.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof SubExpr
		and target_6.getParent().(PointerDiffExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnpci_823
}

predicate func_7(Parameter vpc_798, Parameter vL_798, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="oldpc"
		and target_7.getQualifier().(VariableAccess).getTarget()=vL_798
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpc_798
}

predicate func_9(Variable vp_822, Variable vnpci_823, Parameter vL_798, SubExpr target_9) {
		target_9.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_9.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_798
		and target_9.getLeftOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="code"
		and target_9.getLeftOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_822
		and target_9.getRightOperand() instanceof Literal
		and target_9.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("changedline")
		and target_9.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_9.getParent().(FunctionCall).getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnpci_823
}

predicate func_10(Parameter vpc_798, Parameter vL_798, AssignExpr target_10) {
		target_10.getLValue().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_10.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_798
		and target_10.getRValue().(VariableAccess).getTarget()=vpc_798
}

predicate func_11(Parameter vpc_798, Variable vp_822, Variable vnpci_823, Parameter vL_798, LogicalOrExpr target_11) {
		target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnpci_823
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vpc_798
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_798
		and target_11.getAnOperand().(FunctionCall).getTarget().hasName("changedline")
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_11.getAnOperand().(FunctionCall).getArgument(1) instanceof SubExpr
		and target_11.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnpci_823
}

predicate func_12(Variable vp_822, Variable vnpci_823, FunctionCall target_12) {
		target_12.getTarget().hasName("luaG_getfuncline")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_12.getArgument(1).(VariableAccess).getTarget()=vnpci_823
}

predicate func_13(Parameter vL_798, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("luaD_hook")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_798
		and target_13.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_13.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_13.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_13.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_14(Parameter vL_798, EqualityOperation target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="status"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_798
		and target_14.getAnOperand().(Literal).getValue()="1"
}

predicate func_15(BitwiseAndExpr target_15) {
		target_15.getLeftOperand().(VariableAccess).getTarget().getType().hasName("lu_byte")
		and target_15.getRightOperand().(BinaryBitwiseOperation).getValue()="4"
}

from Function func, Parameter vpc_798, Variable vp_822, Variable vnpci_823, Parameter vL_798, DeclStmt target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, SubExpr target_9, AssignExpr target_10, LogicalOrExpr target_11, FunctionCall target_12, ExprStmt target_13, EqualityOperation target_14, BitwiseAndExpr target_15
where
not func_0(vp_822, target_11, target_12)
and not func_2(vnpci_823, vL_798, target_12, target_13, target_14)
and func_3(target_15, func, target_3)
and func_4(vp_822, vnpci_823, target_4)
and func_5(vL_798, target_5)
and func_6(vp_822, vnpci_823, vL_798, target_6)
and func_7(vpc_798, vL_798, target_7)
and func_9(vp_822, vnpci_823, vL_798, target_9)
and func_10(vpc_798, vL_798, target_10)
and func_11(vpc_798, vp_822, vnpci_823, vL_798, target_11)
and func_12(vp_822, vnpci_823, target_12)
and func_13(vL_798, target_13)
and func_14(vL_798, target_14)
and func_15(target_15)
and vpc_798.getType().hasName("const Instruction *")
and vp_822.getType().hasName("const Proto *")
and vnpci_823.getType().hasName("int")
and vL_798.getType().hasName("lua_State *")
and vpc_798.getFunction() = func
and vp_822.(LocalVariable).getFunction() = func
and vnpci_823.(LocalVariable).getFunction() = func
and vL_798.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
