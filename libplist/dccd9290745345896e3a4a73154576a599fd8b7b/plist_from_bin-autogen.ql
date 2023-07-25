/**
 * @name libplist-dccd9290745345896e3a4a73154576a599fd8b7b-plist_from_bin
 * @id cpp/libplist/dccd9290745345896e3a4a73154576a599fd8b7b/plist-from-bin
 * @description libplist-dccd9290745345896e3a4a73154576a599fd8b7b-src/bplist.c-plist_from_bin CVE-2017-6437
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voffset_table_771, BlockStmt target_4, LogicalOrExpr target_5, ExprStmt target_6) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=voffset_table_771
		and target_0.getAnOperand() instanceof MulExpr
		and target_0.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable voffset_size_767, Variable vnum_objects_769, MulExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vnum_objects_769
		and target_1.getRightOperand().(VariableAccess).getTarget()=voffset_size_767
}

predicate func_2(Variable voffset_table_771, VariableAccess target_2) {
		target_2.getTarget()=voffset_table_771
}

predicate func_3(Variable voffset_table_771, BlockStmt target_4, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=voffset_table_771
		and target_3.getAnOperand() instanceof MulExpr
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(EmptyStmt).toString() = ";"
		and target_4.getStmt(1).(ReturnStmt).toString() = "return ..."
}

predicate func_5(Variable voffset_table_771, LogicalOrExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_table_771
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_table_771
}

predicate func_6(Variable voffset_table_771, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="offset_table"
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffset_table_771
}

from Function func, Variable voffset_size_767, Variable vnum_objects_769, Variable voffset_table_771, MulExpr target_1, VariableAccess target_2, PointerArithmeticOperation target_3, BlockStmt target_4, LogicalOrExpr target_5, ExprStmt target_6
where
not func_0(voffset_table_771, target_4, target_5, target_6)
and func_1(voffset_size_767, vnum_objects_769, target_1)
and func_2(voffset_table_771, target_2)
and func_3(voffset_table_771, target_4, target_3)
and func_4(target_4)
and func_5(voffset_table_771, target_5)
and func_6(voffset_table_771, target_6)
and voffset_size_767.getType().hasName("uint8_t")
and vnum_objects_769.getType().hasName("uint64_t")
and voffset_table_771.getType().hasName("const char *")
and voffset_size_767.getParentScope+() = func
and vnum_objects_769.getParentScope+() = func
and voffset_table_771.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
