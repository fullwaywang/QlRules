/**
 * @name wireshark-bdc33cfaecb1b4cf2c114ed9015713ddf8569a60-vwr_read_s3_W_rec
 * @id cpp/wireshark/bdc33cfaecb1b4cf2c114ed9015713ddf8569a60/vwr-read-s3-W-rec
 * @description wireshark-bdc33cfaecb1b4cf2c114ed9015713ddf8569a60-wiretap/vwr.c-vwr_read_s3_W_rec CVE-2018-19627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrec_1819, ExprStmt target_6, AddressOfExpr target_7) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrec_1819
		and target_0.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vrec_1819, Variable vstats_offset_1826, AddExpr target_2) {
		target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstats_offset_1826
		and target_2.getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_2.getAnOperand().(Literal).getValue()="12"
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrec_1819
}

*/
/*predicate func_3(Parameter vrec_1819, Variable vstats_offset_1826, VariableAccess target_3) {
		target_3.getTarget()=vrec_1819
		and target_3.getParent().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstats_offset_1826
		and target_3.getParent().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_3.getParent().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="12"
}

*/
predicate func_4(Parameter vrec_1819, AddressOfExpr target_4) {
		target_4.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrec_1819
		and target_4.getOperand().(ArrayExpr).getArrayOffset() instanceof AddExpr
		and target_4.getParent().(AssignExpr).getRValue() = target_4
}

predicate func_6(Parameter vrec_1819, Variable vstats_offset_1826, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrec_1819
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstats_offset_1826
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="16"
}

predicate func_7(Parameter vrec_1819, Variable vstats_offset_1826, AddressOfExpr target_7) {
		target_7.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrec_1819
		and target_7.getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstats_offset_1826
		and target_7.getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="16"
}

from Function func, Parameter vrec_1819, Variable vstats_offset_1826, AddressOfExpr target_4, ExprStmt target_6, AddressOfExpr target_7
where
not func_0(vrec_1819, target_6, target_7)
and func_4(vrec_1819, target_4)
and func_6(vrec_1819, vstats_offset_1826, target_6)
and func_7(vrec_1819, vstats_offset_1826, target_7)
and vrec_1819.getType().hasName("const guint8 *")
and vstats_offset_1826.getType().hasName("int")
and vrec_1819.getParentScope+() = func
and vstats_offset_1826.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
