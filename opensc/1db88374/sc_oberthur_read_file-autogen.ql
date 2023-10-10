/**
 * @name opensc-1db88374-sc_oberthur_read_file
 * @id cpp/opensc/1db88374/sc-oberthur-read-file
 * @description opensc-1db88374-src/libopensc/pkcs15-oberthur.c-sc_oberthur_read_file CVE-2021-42779
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrv_241, VariableAccess target_0) {
		target_0.getTarget()=vrv_241
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_pkcs15_get_objects")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1537"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="16"
}

predicate func_1(Variable vrv_241, BlockStmt target_8, VariableAccess target_1) {
		target_1.getTarget()=vrv_241
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_8
}

predicate func_2(Variable vrv_241, BlockStmt target_9, VariableAccess target_2) {
		target_2.getTarget()=vrv_241
		and target_2.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_9
}

/*predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_5(BlockStmt target_9, Function func) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_5.getGreaterOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen()=target_9
		and target_5.getEnclosingFunction() = func)
}

predicate func_7(Variable vrv_241, BlockStmt target_9, ExprStmt target_10, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vrv_241
		and target_7.getAnOperand() instanceof Literal
		and target_7.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
}

predicate func_8(BlockStmt target_8) {
		target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log")
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="compare PIN/ACL refs:%i/%i, method:%i/%i"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="reference"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pin"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="key_ref"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="auth_method"
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="method"
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_file_free")
		and target_9.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_9.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getStmt(3).(DoStmt).getCondition() instanceof Literal
		and target_9.getStmt(3).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_9.getStmt(3).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
}

predicate func_10(Variable vrv_241, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrv_241
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_pkcs15_get_objects")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1537"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="16"
}

from Function func, Variable vrv_241, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, EqualityOperation target_7, BlockStmt target_8, BlockStmt target_9, ExprStmt target_10
where
func_0(vrv_241, target_0)
and func_1(vrv_241, target_8, target_1)
and func_2(vrv_241, target_9, target_2)
and not func_5(target_9, func)
and func_7(vrv_241, target_9, target_10, target_7)
and func_8(target_8)
and func_9(target_9)
and func_10(vrv_241, target_10)
and vrv_241.getType().hasName("int")
and vrv_241.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
