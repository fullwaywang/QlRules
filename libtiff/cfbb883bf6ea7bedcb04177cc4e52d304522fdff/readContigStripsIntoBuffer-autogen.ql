/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-readContigStripsIntoBuffer
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/readContigStripsIntoBuffer
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-readContigStripsIntoBuffer CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="Strip %u: read %d bytes, strip size %u"
		and not target_3.getValue()="Strip %u: read %ld bytes, strip size %lu"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, StringLiteral target_4) {
		target_4.getValue()="Error reading strip %u after %u rows"
		and not target_4.getValue()="Error reading strip %u after %lu rows"
		and target_4.getEnclosingFunction() = func
}

predicate func_8(Variable vbytes_read_3828, Variable vstripsize_3830, LogicalAndExpr target_11, ExprStmt target_12, VariableAccess target_8) {
		target_8.getTarget()=vbytes_read_3828
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=""
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstripsize_3830
		and target_8.getLocation().isBefore(target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
}

/*predicate func_9(Variable vbytes_read_3828, Variable vstripsize_3830, LogicalAndExpr target_11, ExprStmt target_12, VariableAccess target_9) {
		target_9.getTarget()=vstripsize_3830
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=""
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbytes_read_3828
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_9.getLocation().isBefore(target_12.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
}

*/
predicate func_10(Variable vrows_3831, VariableAccess target_10) {
		target_10.getTarget()=vrows_3831
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()=""
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_11(Variable vbytes_read_3828, LogicalAndExpr target_11) {
		target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_read_3828
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_12(Variable vstripsize_3830, ExprStmt target_12) {
		target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_12.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vstripsize_3830
}

from Function func, Variable vbytes_read_3828, Variable vstripsize_3830, Variable vrows_3831, StringLiteral target_3, StringLiteral target_4, VariableAccess target_8, VariableAccess target_10, LogicalAndExpr target_11, ExprStmt target_12
where
func_3(func, target_3)
and func_4(func, target_4)
and func_8(vbytes_read_3828, vstripsize_3830, target_11, target_12, target_8)
and func_10(vrows_3831, target_10)
and func_11(vbytes_read_3828, target_11)
and func_12(vstripsize_3830, target_12)
and vbytes_read_3828.getType().hasName("int32_t")
and vstripsize_3830.getType().hasName("uint32_t")
and vrows_3831.getType().hasName("uint32_t")
and vbytes_read_3828.(LocalVariable).getFunction() = func
and vstripsize_3830.(LocalVariable).getFunction() = func
and vrows_3831.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
