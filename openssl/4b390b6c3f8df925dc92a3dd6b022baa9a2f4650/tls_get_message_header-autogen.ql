/**
 * @name openssl-4b390b6c3f8df925dc92a3dd6b022baa9a2f4650-tls_get_message_header
 * @id cpp/openssl/4b390b6c3f8df925dc92a3dd6b022baa9a2f4650/tls-get-message-header
 * @description openssl-4b390b6c3f8df925dc92a3dd6b022baa9a2f4650-ssl/statem/statem_lib.c-tls_get_message_header CVE-2016-6307
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_345, Variable vl_346, FunctionCall target_11, ExprStmt target_0) {
		target_0.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_346
		and target_0.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_0.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_345
		and target_0.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_345
		and target_0.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_1(Parameter vs_341, Variable vl_346, FunctionCall target_11, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vl_346
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_2(Parameter vs_341, FunctionCall target_11, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="init_msg"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_3(Parameter vs_341, FunctionCall target_11, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="init_num"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Parameter vs_341, Variable vl_346, FunctionCall target_11, IfStmt target_4) {
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vl_346
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_346
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

/*predicate func_5(LogicalAndExpr target_12, Function func, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_5.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_5.getEnclosingFunction() = func
}

*/
/*predicate func_6(LogicalAndExpr target_12, Function func, GotoStmt target_6) {
		target_6.toString() = "goto ..."
		and target_6.getName() ="err"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_6.getEnclosingFunction() = func
}

*/
predicate func_7(Parameter vs_341, Variable vl_346, FunctionCall target_11, IfStmt target_7) {
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vl_346
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vl_346
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_7.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

/*predicate func_8(LogicalAndExpr target_13, Function func, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_8.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_8.getEnclosingFunction() = func
}

*/
/*predicate func_9(LogicalAndExpr target_13, Function func, GotoStmt target_9) {
		target_9.toString() = "goto ..."
		and target_9.getName() ="err"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_9.getEnclosingFunction() = func
}

*/
predicate func_10(Function func, LabelStmt target_10) {
		target_10.toString() = "label ...:"
		and target_10.getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Parameter vs_341, FunctionCall target_11) {
		target_11.getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_11.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_11.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_341
}

predicate func_12(Variable vl_346, LogicalAndExpr target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vl_346
		and target_12.getAnOperand() instanceof NotExpr
}

predicate func_13(Variable vl_346, LogicalAndExpr target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vl_346
		and target_13.getAnOperand() instanceof NotExpr
}

from Function func, Parameter vs_341, Variable vp_345, Variable vl_346, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, IfStmt target_4, IfStmt target_7, LabelStmt target_10, FunctionCall target_11, LogicalAndExpr target_12, LogicalAndExpr target_13
where
func_0(vp_345, vl_346, target_11, target_0)
and func_1(vs_341, vl_346, target_11, target_1)
and func_2(vs_341, target_11, target_2)
and func_3(vs_341, target_11, target_3)
and func_4(vs_341, vl_346, target_11, target_4)
and func_7(vs_341, vl_346, target_11, target_7)
and func_10(func, target_10)
and func_11(vs_341, target_11)
and func_12(vl_346, target_12)
and func_13(vl_346, target_13)
and vs_341.getType().hasName("SSL *")
and vp_345.getType().hasName("unsigned char *")
and vl_346.getType().hasName("unsigned long")
and vs_341.getParentScope+() = func
and vp_345.getParentScope+() = func
and vl_346.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
