/**
 * @name libarchive-39fc59391b7cf2a007bffce280c1e3e66674258f-archive_read_format_iso9660_read_header
 * @id cpp/libarchive/39fc59391b7cf2a007bffce280c1e3e66674258f/archive-read-format-iso9660-read-header
 * @description libarchive-39fc59391b7cf2a007bffce280c1e3e66674258f-libarchive/archive_read_support_format_iso9660.c-archive_read_format_iso9660_read_header CVE-2015-8930
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_5, Function func) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(UnaryMinusExpr).getValue()="-30"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Parameter va_1166, Parameter ventry_1167, PointerFieldAccess target_6, AddressOfExpr target_7, AddressOfExpr target_8, ExprStmt target_9, FunctionCall target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const char *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1166
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Pathname is too long"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-30"
		and target_2.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_entry_set_pathname")
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_1167
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable viso9660_1169, PointerFieldAccess target_6, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pathname"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Variable viso9660_1169, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("build_pathname_utf16be")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="utf16be_path"
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1024"
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="utf16be_path_len"
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable viso9660_1169, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="seenJoliet"
		and target_6.getQualifier().(VariableAccess).getTarget()=viso9660_1169
}

predicate func_7(Parameter va_1166, AddressOfExpr target_7) {
		target_7.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1166
}

predicate func_8(Parameter va_1166, AddressOfExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1166
}

predicate func_9(Parameter ventry_1167, Variable viso9660_1169, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_archive_entry_copy_pathname_l")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_1167
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="utf16be_path"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="utf16be_path_len"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="sconv_utf16be"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viso9660_1169
}

predicate func_10(Parameter ventry_1167, FunctionCall target_10) {
		target_10.getTarget().hasName("archive_entry_pathname")
		and target_10.getArgument(0).(VariableAccess).getTarget()=ventry_1167
}

from Function func, Parameter va_1166, Parameter ventry_1167, Variable viso9660_1169, ExprStmt target_4, EqualityOperation target_5, PointerFieldAccess target_6, AddressOfExpr target_7, AddressOfExpr target_8, ExprStmt target_9, FunctionCall target_10
where
not func_0(target_5, func)
and not func_2(va_1166, ventry_1167, target_6, target_7, target_8, target_9, target_10)
and func_4(viso9660_1169, target_6, target_4)
and func_5(viso9660_1169, target_5)
and func_6(viso9660_1169, target_6)
and func_7(va_1166, target_7)
and func_8(va_1166, target_8)
and func_9(ventry_1167, viso9660_1169, target_9)
and func_10(ventry_1167, target_10)
and va_1166.getType().hasName("archive_read *")
and ventry_1167.getType().hasName("archive_entry *")
and viso9660_1169.getType().hasName("iso9660 *")
and va_1166.getParentScope+() = func
and ventry_1167.getParentScope+() = func
and viso9660_1169.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
