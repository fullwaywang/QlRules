/**
 * @name libplist-fdebf8b319b9280cd0e9b4382f2c7cbf26ef9325-plist_from_bin
 * @id cpp/libplist/fdebf8b319b9280cd0e9b4382f2c7cbf26ef9325/plist-from-bin
 * @description libplist-fdebf8b319b9280cd0e9b4382f2c7cbf26ef9325-src/bplist.c-plist_from_bin CVE-2017-7982
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnum_objects_773, BlockStmt target_12, VariableAccess target_0) {
		target_0.getTarget()=vnum_objects_773
		and target_0.getParent().(LTExpr).getLesserOperand() instanceof MulExpr
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_1(Variable vnum_objects_773, VariableAccess target_1) {
		target_1.getTarget()=vnum_objects_773
}

predicate func_2(Variable voffset_size_771, Variable vnum_objects_773, EqualityOperation target_13, RelationalOperation target_15) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("__builtin_umulll_overflow")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vnum_objects_773
		and target_2.getArgument(1).(VariableAccess).getTarget()=voffset_size_771
		and target_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
		and target_15.getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable voffset_table_775, Variable vend_data_777, BlockStmt target_16, LogicalOrExpr target_18) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_data_777
		and target_3.getParent().(IfStmt).getThen()=target_16
		and target_18.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable voffset_table_775, Variable vnum_objects_773, BlockStmt target_12, ExprStmt target_19) {
	exists(PointerArithmeticOperation target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_4.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_4.getParent().(LTExpr).getLesserOperand() instanceof MulExpr
		and target_4.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnum_objects_773
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
/*predicate func_6(Variable voffset_table_775, Variable vend_data_777, BlockStmt target_16) {
	exists(PointerArithmeticOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_6.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_6.getParent().(GTExpr).getGreaterOperand() instanceof AddExpr
		and target_6.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_data_777
		and target_6.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_16)
}

*/
predicate func_7(Variable vnum_objects_773, VariableAccess target_7) {
		target_7.getTarget()=vnum_objects_773
}

predicate func_8(Variable voffset_size_771, VariableAccess target_8) {
		target_8.getTarget()=voffset_size_771
}

predicate func_9(Variable voffset_table_775, VariableAccess target_9) {
		target_9.getTarget()=voffset_table_775
}

predicate func_10(Variable voffset_size_771, Variable vnum_objects_773, BlockStmt target_12, EqualityOperation target_13, RelationalOperation target_15, MulExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vnum_objects_773
		and target_10.getRightOperand().(VariableAccess).getTarget()=voffset_size_771
		and target_10.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vnum_objects_773
		and target_10.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getRightOperand().(VariableAccess).getLocation())
		and target_15.getLesserOperand().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation())
}

predicate func_11(Variable voffset_table_775, Variable vend_data_777, Variable voffset_size_771, Variable vnum_objects_773, BlockStmt target_16, AddExpr target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_11.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnum_objects_773
		and target_11.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=voffset_size_771
		and target_11.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_data_777
		and target_11.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0).(EmptyStmt).toString() = ";"
		and target_12.getStmt(1).(ReturnStmt).toString() = "return ..."
}

predicate func_13(Variable voffset_size_771, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=voffset_size_771
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_15(Variable vnum_objects_773, RelationalOperation target_15) {
		 (target_15 instanceof GEExpr or target_15 instanceof LEExpr)
		and target_15.getLesserOperand().(VariableAccess).getTarget()=vnum_objects_773
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0).(EmptyStmt).toString() = ";"
		and target_16.getStmt(1).(ReturnStmt).toString() = "return ..."
}

predicate func_18(Variable voffset_table_775, Variable vend_data_777, LogicalOrExpr target_18) {
		target_18.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_table_775
		and target_18.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_data_777
}

predicate func_19(Variable voffset_table_775, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="offset_table"
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffset_table_775
}

from Function func, Variable voffset_table_775, Variable vend_data_777, Variable voffset_size_771, Variable vnum_objects_773, VariableAccess target_0, VariableAccess target_1, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, MulExpr target_10, AddExpr target_11, BlockStmt target_12, EqualityOperation target_13, RelationalOperation target_15, BlockStmt target_16, LogicalOrExpr target_18, ExprStmt target_19
where
func_0(vnum_objects_773, target_12, target_0)
and func_1(vnum_objects_773, target_1)
and not func_2(voffset_size_771, vnum_objects_773, target_13, target_15)
and not func_3(voffset_table_775, vend_data_777, target_16, target_18)
and func_7(vnum_objects_773, target_7)
and func_8(voffset_size_771, target_8)
and func_9(voffset_table_775, target_9)
and func_10(voffset_size_771, vnum_objects_773, target_12, target_13, target_15, target_10)
and func_11(voffset_table_775, vend_data_777, voffset_size_771, vnum_objects_773, target_16, target_11)
and func_12(target_12)
and func_13(voffset_size_771, target_13)
and func_15(vnum_objects_773, target_15)
and func_16(target_16)
and func_18(voffset_table_775, vend_data_777, target_18)
and func_19(voffset_table_775, target_19)
and voffset_table_775.getType().hasName("const char *")
and vend_data_777.getType().hasName("const char *")
and voffset_size_771.getType().hasName("uint8_t")
and vnum_objects_773.getType().hasName("uint64_t")
and voffset_table_775.getParentScope+() = func
and vend_data_777.getParentScope+() = func
and voffset_size_771.getParentScope+() = func
and vnum_objects_773.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
