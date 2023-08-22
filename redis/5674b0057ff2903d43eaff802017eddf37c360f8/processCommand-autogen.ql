/**
 * @name redis-5674b0057ff2903d43eaff802017eddf37c360f8-processCommand
 * @id cpp/redis/5674b0057ff2903d43eaff802017eddf37c360f8/processCommand
 * @description redis-5674b0057ff2903d43eaff802017eddf37c360f8-src/server.c-processCommand CVE-2021-32675
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_3552, BlockStmt target_5, LogicalOrExpr target_6, NotExpr target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("authRequired")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vc_3552
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func, BinaryBitwiseOperation target_1) {
		target_1.getValue()="2"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vc_3552, VariableAccess target_2) {
		target_2.getTarget()=vc_3552
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vauth_required_3595, BlockStmt target_5, VariableAccess target_4) {
		target_4.getTarget()=vauth_required_3595
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vc_3552, BlockStmt target_5) {
		target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3552
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="32768"
		and target_5.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rejectCommand")
		and target_5.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3552
		and target_5.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="noautherr"
		and target_5.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sharedObjectsStruct")
		and target_5.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_6(Parameter vc_3552, LogicalOrExpr target_6) {
		target_6.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_6.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_6.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3552
		and target_6.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="512"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="proc"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3552
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="cmd_inv_flags"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mstate"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3552
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="512"
}

predicate func_7(Parameter vc_3552, NotExpr target_7) {
		target_7.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_7.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_7.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3552
		and target_7.getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="32768"
}

from Function func, Parameter vc_3552, Variable vauth_required_3595, BinaryBitwiseOperation target_1, VariableAccess target_2, DeclStmt target_3, VariableAccess target_4, BlockStmt target_5, LogicalOrExpr target_6, NotExpr target_7
where
not func_0(vc_3552, target_5, target_6, target_7)
and func_1(func, target_1)
and func_2(vc_3552, target_2)
and func_3(func, target_3)
and func_4(vauth_required_3595, target_5, target_4)
and func_5(vc_3552, target_5)
and func_6(vc_3552, target_6)
and func_7(vc_3552, target_7)
and vc_3552.getType().hasName("client *")
and vauth_required_3595.getType().hasName("int")
and vc_3552.getFunction() = func
and vauth_required_3595.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
