/**
 * @name curl-517b06d657aceb11a234b05cc891170c367ab80d-ConnectionExists
 * @id cpp/curl/517b06d657aceb11a234b05cc891170c367ab80d/ConnectionExists
 * @description curl-517b06d657aceb11a234b05cc891170c367ab80d-lib/url.c-ConnectionExists CVE-2014-0138
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_2899, LogicalOrExpr target_5, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="protocol"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Function func, BinaryBitwiseOperation target_1) {
		target_1.getValue()="4"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vneedle_2899, BlockStmt target_6, LogicalOrExpr target_5) {
	exists(NotExpr target_2 |
		target_2.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_2.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_2.getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="protocol"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
		and target_2.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vneedle_2899, LogicalOrExpr target_5) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="handler"
		and target_3.getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vneedle_2899, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="handler"
		and target_4.getQualifier().(VariableAccess).getTarget()=vneedle_2899
}

predicate func_5(Parameter vneedle_2899, LogicalOrExpr target_5) {
		target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
}

predicate func_6(Parameter vneedle_2899, BlockStmt target_6) {
		target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_2899
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_6.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
}

from Function func, Parameter vneedle_2899, PointerFieldAccess target_0, BinaryBitwiseOperation target_1, PointerFieldAccess target_4, LogicalOrExpr target_5, BlockStmt target_6
where
func_0(vneedle_2899, target_5, target_0)
and func_1(func, target_1)
and not func_2(vneedle_2899, target_6, target_5)
and func_4(vneedle_2899, target_4)
and func_5(vneedle_2899, target_5)
and func_6(vneedle_2899, target_6)
and vneedle_2899.getType().hasName("connectdata *")
and vneedle_2899.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
