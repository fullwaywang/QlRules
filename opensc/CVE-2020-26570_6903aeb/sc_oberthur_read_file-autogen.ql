/**
 * @name opensc-6903aebfddc466d966c7b865fae34572bf3ed23e-sc_oberthur_read_file
 * @id cpp/opensc/6903aebfddc466d966c7b865fae34572bf3ed23e/sc-oberthur-read-file
 * @description opensc-6903aebfddc466d966c7b865fae34572bf3ed23e-src/libopensc/pkcs15-oberthur.c-sc_oberthur_read_file CVE-2020-26570
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vrec_274, VariableAccess target_0) {
		target_0.getTarget()=vrec_274
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_1(Variable vrec_274, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrec_274
}

*/
/*predicate func_2(Variable vsz_240, Variable voffs_275, VariableAccess target_2) {
		target_2.getTarget()=vsz_240
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffs_275
}

*/
/*predicate func_3(Variable vsz_240, Variable voffs_275, ExprStmt target_11, VariableAccess target_3) {
		target_3.getTarget()=voffs_275
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_240
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
predicate func_7(Variable vrec_274, ExprStmt target_12) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vrec_274
		and target_7.getRValue().(Literal).getValue()="1"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getLValue().(VariableAccess).getLocation()))
}

predicate func_8(Variable vfile_238, Variable vrec_274, FunctionCall target_13, PostfixIncrExpr target_14, ExprStmt target_12) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrec_274
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="record_count"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_238
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(VariableAccess).getLocation())
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_9(Variable vsz_240, Variable voffs_275, EqualityOperation target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_240
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffs_275
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(4)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_10(Variable vrv_241, Variable vrec_len_276, AssignExpr target_10) {
		target_10.getLValue().(VariableAccess).getTarget()=vrec_len_276
		and target_10.getRValue().(VariableAccess).getTarget()=vrv_241
}

predicate func_11(Variable vsz_240, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsz_240
}

predicate func_12(Variable vrv_241, Variable vrec_274, Variable voffs_275, Variable vrec_len_276, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrv_241
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_read_record")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrec_274
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_275
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vrec_len_276
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="256"
}

predicate func_13(Variable vfile_238, FunctionCall target_13) {
		target_13.getTarget().hasName("sc_file_get_acl_entry")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vfile_238
		and target_13.getArgument(1).(Literal).getValue()="22"
}

predicate func_14(Variable vrec_274, PostfixIncrExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vrec_274
}

predicate func_15(Variable vfile_238, EqualityOperation target_15) {
		target_15.getAnOperand().(PointerFieldAccess).getTarget().getName()="ef_structure"
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_238
		and target_15.getAnOperand().(Literal).getValue()="1"
}

predicate func_16(Variable vsz_240, Variable vrv_241, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrv_241
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_read_binary")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsz_240
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_17(Variable vrv_241, Variable voffs_275, ExprStmt target_17) {
		target_17.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffs_275
		and target_17.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrv_241
		and target_17.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_18(Variable vsz_240, Variable voffs_275, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_240
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffs_275
}

from Function func, Variable vfile_238, Variable vsz_240, Variable vrv_241, Variable vrec_274, Variable voffs_275, Variable vrec_len_276, AssignExpr target_10, ExprStmt target_11, ExprStmt target_12, FunctionCall target_13, PostfixIncrExpr target_14, EqualityOperation target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18
where
not func_7(vrec_274, target_12)
and not func_8(vfile_238, vrec_274, target_13, target_14, target_12)
and not func_9(vsz_240, voffs_275, target_15, target_16, target_17, target_18)
and func_10(vrv_241, vrec_len_276, target_10)
and func_11(vsz_240, target_11)
and func_12(vrv_241, vrec_274, voffs_275, vrec_len_276, target_12)
and func_13(vfile_238, target_13)
and func_14(vrec_274, target_14)
and func_15(vfile_238, target_15)
and func_16(vsz_240, vrv_241, target_16)
and func_17(vrv_241, voffs_275, target_17)
and func_18(vsz_240, voffs_275, target_18)
and vfile_238.getType().hasName("sc_file *")
and vsz_240.getType().hasName("size_t")
and vrv_241.getType().hasName("int")
and vrec_274.getType().hasName("int")
and voffs_275.getType().hasName("int")
and vrec_len_276.getType().hasName("int")
and vfile_238.getParentScope+() = func
and vsz_240.getParentScope+() = func
and vrv_241.getParentScope+() = func
and vrec_274.getParentScope+() = func
and voffs_275.getParentScope+() = func
and vrec_len_276.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
