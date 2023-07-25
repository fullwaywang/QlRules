/**
 * @name libarchive-d0331e8e5b05b475f20b1f3101fe1ad772d7e7e7-zip_read_mac_metadata
 * @id cpp/libarchive/d0331e8e5b05b475f20b1f3101fe1ad772d7e7e7/zip-read-mac-metadata
 * @description libarchive-d0331e8e5b05b475f20b1f3101fe1ad772d7e7e7-libarchive/archive_read_support_format_zip.c-zip_read_mac_metadata CVE-2016-1541
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter va_2769, Parameter vrsrc_2770, PointerFieldAccess target_3, AddressOfExpr target_4, AddressOfExpr target_5, SwitchStmt target_6, FunctionCall target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="uncompressed_size"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="compressed_size"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Malformed OS X metadata entry: inconsistent size"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-30"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter va_2769, Parameter vrsrc_2770, AddressOfExpr target_8, AddressOfExpr target_9, ExprStmt target_10, ExprStmt target_11, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="compressed_size"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="4194304"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Mac metadata is too large: %jd > 4M bytes"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="compressed_size"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-20"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmetadata_bytes_2775, Variable vbytes_avail_2824, PointerFieldAccess target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytes_avail_2824
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmetadata_bytes_2775
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_avail_2824
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmetadata_bytes_2775
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vrsrc_2770, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="compression"
		and target_3.getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_4(Parameter va_2769, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
}

predicate func_5(Parameter va_2769, AddressOfExpr target_5) {
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
}

predicate func_6(Parameter va_2769, Parameter vrsrc_2770, SwitchStmt target_6) {
		target_6.getExpr().(PointerFieldAccess).getTarget().getName()="compression"
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
		and target_6.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(1).(SwitchCase).getExpr().(Literal).getValue()="8"
		and target_6.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_6.getStmt().(BlockStmt).getStmt(3).(SwitchCase).toString() = "default: "
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unsupported ZIP compression method (%s)"
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("compression_name")
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="compression"
		and target_6.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_7(Parameter vrsrc_2770, FunctionCall target_7) {
		target_7.getTarget().hasName("compression_name")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="compression"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_8(Parameter va_2769, AddressOfExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
}

predicate func_9(Parameter va_2769, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
}

predicate func_10(Parameter va_2769, Parameter vrsrc_2770, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2769
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_10.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Mac metadata is too large: %jd > 4M bytes"
		and target_10.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="uncompressed_size"
		and target_10.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_11(Parameter vrsrc_2770, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="uncompressed_size"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_12(Parameter vrsrc_2770, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="compression"
		and target_12.getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_13(Parameter vrsrc_2770, Variable vmetadata_bytes_2775, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmetadata_bytes_2775
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="uncompressed_size"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsrc_2770
}

predicate func_14(Variable vmetadata_bytes_2775, ExprStmt target_14) {
		target_14.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vmetadata_bytes_2775
}

predicate func_15(Variable vbytes_avail_2824, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_avail_2824
}

predicate func_16(Variable vbytes_avail_2824, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_16.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_avail_2824
}

from Function func, Parameter va_2769, Parameter vrsrc_2770, Variable vmetadata_bytes_2775, Variable vbytes_avail_2824, PointerFieldAccess target_3, AddressOfExpr target_4, AddressOfExpr target_5, SwitchStmt target_6, FunctionCall target_7, AddressOfExpr target_8, AddressOfExpr target_9, ExprStmt target_10, ExprStmt target_11, PointerFieldAccess target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16
where
not func_0(va_2769, vrsrc_2770, target_3, target_4, target_5, target_6, target_7)
and not func_1(va_2769, vrsrc_2770, target_8, target_9, target_10, target_11, func)
and not func_2(vmetadata_bytes_2775, vbytes_avail_2824, target_12, target_13, target_14, target_15, target_16)
and func_3(vrsrc_2770, target_3)
and func_4(va_2769, target_4)
and func_5(va_2769, target_5)
and func_6(va_2769, vrsrc_2770, target_6)
and func_7(vrsrc_2770, target_7)
and func_8(va_2769, target_8)
and func_9(va_2769, target_9)
and func_10(va_2769, vrsrc_2770, target_10)
and func_11(vrsrc_2770, target_11)
and func_12(vrsrc_2770, target_12)
and func_13(vrsrc_2770, vmetadata_bytes_2775, target_13)
and func_14(vmetadata_bytes_2775, target_14)
and func_15(vbytes_avail_2824, target_15)
and func_16(vbytes_avail_2824, target_16)
and va_2769.getType().hasName("archive_read *")
and vrsrc_2770.getType().hasName("zip_entry *")
and vmetadata_bytes_2775.getType().hasName("size_t")
and vbytes_avail_2824.getType().hasName("ssize_t")
and va_2769.getParentScope+() = func
and vrsrc_2770.getParentScope+() = func
and vmetadata_bytes_2775.getParentScope+() = func
and vbytes_avail_2824.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
