/**
 * @name php-e0f5d62bd6690169998474b62f92a8c5ddf0e699-phar_tar_writeheaders_int
 * @id cpp/php/e0f5d62bd6690169998474b62f92a8c5ddf0e699/phar-tar-writeheaders-int
 * @description php-e0f5d62bd6690169998474b62f92a8c5ddf0e699-ext/phar/tar.c-phar_tar_writeheaders_int CVE-2019-9675
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter ventry_698, FunctionCall target_0) {
		target_0.getTarget().hasName("strlen")
		and not target_0.getTarget().hasName("php_strlcpy")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="link"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
}

predicate func_1(Parameter ventry_698, Variable vfp_702, PointerFieldAccess target_8, ExprStmt target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("php_strlcpy")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="link"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="100"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="100"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="error"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_702
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spprintf")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="tar-based phar \"%s\" cannot be created, link \"%s\" is too long for format"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="fname"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="link"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(BinaryBitwiseOperation).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Function func) {
	exists(SizeofExprOperator target_2 |
		target_2.getValue()="100"
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Parameter ventry_698, Variable vfp_702, IfStmt target_10, ExprStmt target_11, IfStmt target_12) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("spprintf")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="error"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_702
		and target_3.getArgument(1).(Literal).getValue()="4096"
		and target_3.getArgument(2).(StringLiteral).getValue()="tar-based phar \"%s\" cannot be created, link \"%s\" is too long for format"
		and target_3.getArgument(3).(PointerFieldAccess).getTarget().getName()="fname"
		and target_3.getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phar"
		and target_3.getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_3.getArgument(4).(PointerFieldAccess).getTarget().getName()="link"
		and target_3.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_10.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vheader_700, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="linkname"
		and target_4.getQualifier().(VariableAccess).getTarget()=vheader_700
}

predicate func_5(Parameter ventry_698, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="link"
		and target_5.getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter ventry_698, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="link"
		and target_6.getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_6.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall
}

predicate func_7(Parameter ventry_698, FunctionCall target_7) {
		target_7.getTarget().hasName("strncpy")
		and target_7.getArgument(0) instanceof ValueFieldAccess
		and target_7.getArgument(1).(PointerFieldAccess).getTarget().getName()="link"
		and target_7.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_7.getArgument(2) instanceof FunctionCall
}

predicate func_8(Parameter ventry_698, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="link"
		and target_8.getQualifier().(VariableAccess).getTarget()=ventry_698
}

predicate func_9(Parameter ventry_698, Variable vfp_702, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("spprintf")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_702
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="tar-based phar \"%s\" cannot be created, file modification time of file \"%s\" is too large for tar file format"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="fname"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phar"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="filename"
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
}

predicate func_10(Parameter ventry_698, IfStmt target_10) {
		target_10.getCondition().(PointerFieldAccess).getTarget().getName()="link"
		and target_10.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_11(Parameter ventry_698, Variable vheader_700, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="crc32"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("phar_tar_checksum")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vheader_700
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="512"
}

predicate func_12(Parameter ventry_698, Variable vfp_702, IfStmt target_12) {
		target_12.getCondition().(PointerFieldAccess).getTarget().getName()="error"
		and target_12.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_702
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spprintf")
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_702
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="tar-based phar \"%s\" cannot be created, checksum of file \"%s\" is too large for tar file format"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="fname"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phar"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="filename"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_698
}

from Function func, Parameter ventry_698, Variable vheader_700, Variable vfp_702, FunctionCall target_0, ValueFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, FunctionCall target_7, PointerFieldAccess target_8, ExprStmt target_9, IfStmt target_10, ExprStmt target_11, IfStmt target_12
where
func_0(ventry_698, target_0)
and not func_1(ventry_698, vfp_702, target_8, target_9)
and func_4(vheader_700, target_4)
and func_5(ventry_698, target_5)
and func_6(ventry_698, target_6)
and func_7(ventry_698, target_7)
and func_8(ventry_698, target_8)
and func_9(ventry_698, vfp_702, target_9)
and func_10(ventry_698, target_10)
and func_11(ventry_698, vheader_700, target_11)
and func_12(ventry_698, vfp_702, target_12)
and ventry_698.getType().hasName("phar_entry_info *")
and vheader_700.getType().hasName("tar_header")
and vfp_702.getType().hasName("_phar_pass_tar_info *")
and ventry_698.getParentScope+() = func
and vheader_700.getParentScope+() = func
and vfp_702.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
