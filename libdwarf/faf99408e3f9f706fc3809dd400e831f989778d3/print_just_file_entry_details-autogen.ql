/**
 * @name libdwarf-faf99408e3f9f706fc3809dd400e831f989778d3-print_just_file_entry_details
 * @id cpp/libdwarf/faf99408e3f9f706fc3809dd400e831f989778d3/print-just-file-entry-details
 * @description libdwarf-faf99408e3f9f706fc3809dd400e831f989778d3-libdwarf/dwarf_print_lines.c-print_just_file_entry_details CVE-2020-28163
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfe_305, Variable vm3_307, ExprStmt target_8, IfStmt target_9) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="fi_file_name"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_0.getThen().(PointerFieldAccess).getTarget().getName()="fi_file_name"
		and target_0.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_0.getElse().(StringLiteral).getValue()="<no file name>"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_s")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vm3_307
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%-20s "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="fi_file_name"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vm3_307, Variable vfilenum_318, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vm3_307
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_u")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="(file-number: %u)\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfilenum_318
}

*/
predicate func_2(Variable vm3_307, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vm3_307
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Variable vfe_305, Variable vm3_307, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="fi_file_name"
		and target_3.getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_s")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vm3_307
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%-20s "
}

predicate func_4(Variable vm3_307, Variable vfilenum_318, RelationalOperation target_10, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_u")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vm3_307
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="(file-number: %u)\n"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfilenum_318
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_5(Variable vfe_305, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="fi_file_name"
		and target_5.getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vfe_305, Variable vm3_307, RelationalOperation target_10, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_s")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vm3_307
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%-20s "
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="fi_file_name"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_7(Variable vfilenum_318, RelationalOperation target_10, ExprStmt target_4, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_u")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="(file-number: %u)\n"
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfilenum_318
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

predicate func_8(Variable vfe_305, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Dwarf_Unsigned")
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="fi_time_last_mod"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
}

predicate func_9(Variable vfe_305, Variable vm3_307, IfStmt target_9) {
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="fi_dir_index_present"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Dwarf_Unsigned")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="fi_dir_index"
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_305
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwarfstring_append_printf_i")
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vm3_307
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="    dir index %d\n"
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("Dwarf_Unsigned")
}

predicate func_10(RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="lc_file_entry_count"
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Dwarf_Line_Context")
		and target_10.getLesserOperand().(Literal).getValue()="9"
}

from Function func, Variable vfe_305, Variable vm3_307, Variable vfilenum_318, AddressOfExpr target_2, PointerFieldAccess target_3, ExprStmt target_4, PointerFieldAccess target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, IfStmt target_9, RelationalOperation target_10
where
not func_0(vfe_305, vm3_307, target_8, target_9)
and func_2(vm3_307, target_2)
and func_3(vfe_305, vm3_307, target_3)
and func_4(vm3_307, vfilenum_318, target_10, target_4)
and func_5(vfe_305, target_5)
and func_6(vfe_305, vm3_307, target_10, target_6)
and func_7(vfilenum_318, target_10, target_4, target_7)
and func_8(vfe_305, target_8)
and func_9(vfe_305, vm3_307, target_9)
and func_10(target_10)
and vfe_305.getType().hasName("Dwarf_File_Entry")
and vm3_307.getType().hasName("dwarfstring")
and vfilenum_318.getType().hasName("unsigned int")
and vfe_305.(LocalVariable).getFunction() = func
and vm3_307.(LocalVariable).getFunction() = func
and vfilenum_318.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
