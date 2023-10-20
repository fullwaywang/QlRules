/**
 * @name php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-ps_srlzr_decode_php_binary
 * @id cpp/php/0d13325b660b5ae64267dffcc9a153c7634fdfe2/ps-srlzr-decode-php-binary
 * @description php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-ext/session/session.c-ps_srlzr_decode_php_binary CVE-2016-7125
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getRValue().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(LogicalOrExpr target_15, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(FunctionCall target_16, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vp_960, Variable vnamelen_963, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnamelen_963
		and target_3.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_960
		and target_3.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-129"
}

predicate func_4(Variable vp_960, Variable vendptr_961, Variable vnamelen_963, IfStmt target_4) {
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnamelen_963
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnamelen_963
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="127"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_960
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnamelen_963
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vendptr_961
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="serialize_lock"
}

predicate func_5(Variable vp_960, Variable vhas_value_962, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhas_value_962
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_960
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_6(Variable vp_960, Variable vnamelen_963, Variable vname_964, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_964
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_string_init")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_960
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnamelen_963
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Variable vp_960, Variable vnamelen_963, ExprStmt target_7) {
		target_7.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_960
		and target_7.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnamelen_963
		and target_7.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

/*predicate func_8(Variable vname_964, FunctionCall target_8) {
		target_8.getTarget().hasName("zend_string_release")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vname_964
}

*/
predicate func_10(Variable vname_964, LogicalOrExpr target_15, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("zend_string_release")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_964
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_11(Variable vname_964, Variable vvar_hash_965, Variable vrv_993, FunctionCall target_16, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("php_set_session_var")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_964
		and target_11.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrv_993
		and target_11.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvar_hash_965
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_12(Variable vname_964, FunctionCall target_12) {
		target_12.getTarget().hasName("zend_string_release")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vname_964
}

predicate func_13(LogicalOrExpr target_15, Function func, ContinueStmt target_13) {
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_13.getEnclosingFunction() = func
}

predicate func_15(LogicalOrExpr target_15) {
		target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("zval *")
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="7"
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="arr"
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("zval *")
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="symbol_table"
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("zend_executor_globals")
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("zval *")
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="http_session_vars"
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("zend_ps_globals")
}

predicate func_16(Variable vp_960, Variable vendptr_961, Variable vvar_hash_965, FunctionCall target_16) {
		target_16.getTarget().hasName("php_var_unserialize")
		and target_16.getArgument(0).(VariableAccess).getTarget().getType().hasName("zval *")
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_960
		and target_16.getArgument(2).(VariableAccess).getTarget()=vendptr_961
		and target_16.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvar_hash_965
}

from Function func, Variable vp_960, Variable vendptr_961, Variable vhas_value_962, Variable vnamelen_963, Variable vname_964, Variable vvar_hash_965, Variable vrv_993, ExprStmt target_3, IfStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_10, ExprStmt target_11, FunctionCall target_12, ContinueStmt target_13, LogicalOrExpr target_15, FunctionCall target_16
where
not func_0(func)
and not func_1(target_15, func)
and not func_2(target_16, func)
and func_3(vp_960, vnamelen_963, target_3)
and func_4(vp_960, vendptr_961, vnamelen_963, target_4)
and func_5(vp_960, vhas_value_962, target_5)
and func_6(vp_960, vnamelen_963, vname_964, target_6)
and func_7(vp_960, vnamelen_963, target_7)
and func_10(vname_964, target_15, target_10)
and func_11(vname_964, vvar_hash_965, vrv_993, target_16, target_11)
and func_12(vname_964, target_12)
and func_13(target_15, func, target_13)
and func_15(target_15)
and func_16(vp_960, vendptr_961, vvar_hash_965, target_16)
and vp_960.getType().hasName("const char *")
and vendptr_961.getType().hasName("const char *")
and vhas_value_962.getType().hasName("int")
and vnamelen_963.getType().hasName("int")
and vname_964.getType().hasName("zend_string *")
and vvar_hash_965.getType().hasName("php_unserialize_data_t")
and vrv_993.getType().hasName("zval")
and vp_960.(LocalVariable).getFunction() = func
and vendptr_961.(LocalVariable).getFunction() = func
and vhas_value_962.(LocalVariable).getFunction() = func
and vnamelen_963.(LocalVariable).getFunction() = func
and vname_964.(LocalVariable).getFunction() = func
and vvar_hash_965.(LocalVariable).getFunction() = func
and vrv_993.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
