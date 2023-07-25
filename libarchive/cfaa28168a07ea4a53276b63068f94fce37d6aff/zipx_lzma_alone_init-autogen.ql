/**
 * @name libarchive-cfaa28168a07ea4a53276b63068f94fce37d6aff-zipx_lzma_alone_init
 * @id cpp/libarchive/cfaa28168a07ea4a53276b63068f94fce37d6aff/zipx-lzma-alone-init
 * @description libarchive-cfaa28168a07ea4a53276b63068f94fce37d6aff-libarchive/archive_read_support_format_zip.c-zipx_lzma_alone_init CVE-2022-26280
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vzip_1594, BlockStmt target_2, ExprStmt target_3, NotExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="entry_bytes_remaining"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_1594
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="9"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_1597, Parameter va_1594, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_1597
		and target_1.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__archive_read_ahead")
		and target_1.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_1594
		and target_1.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="9"
		and target_1.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter va_1594, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1594
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Truncated lzma data"
}

predicate func_3(Parameter vzip_1594, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="zipx_lzma_valid"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_1594
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_4(Parameter vzip_1594, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="uncompressed_buffer"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_1594
}

from Function func, Parameter vzip_1594, Variable vp_1597, Parameter va_1594, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, NotExpr target_4
where
not func_0(vzip_1594, target_2, target_3, target_4)
and func_1(vp_1597, va_1594, target_2, target_1)
and func_2(va_1594, target_2)
and func_3(vzip_1594, target_3)
and func_4(vzip_1594, target_4)
and vzip_1594.getType().hasName("zip *")
and vp_1597.getType().hasName("const uint8_t *")
and va_1594.getType().hasName("archive_read *")
and vzip_1594.getParentScope+() = func
and vp_1597.getParentScope+() = func
and va_1594.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
