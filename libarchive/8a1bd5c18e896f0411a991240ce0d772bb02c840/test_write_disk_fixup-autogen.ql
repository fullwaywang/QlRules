/**
 * @name libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-test_write_disk_fixup
 * @id cpp/libarchive/8a1bd5c18e896f0411a991240ce0d772bb02c840/test-write-disk-fixup
 * @description libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-libarchive/test/test_write_disk_fixup.c-test_write_disk_fixup CVE-2021-31566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="dir"
		and not target_0.getValue()="dir1/"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vae_36, BitwiseOrExpr target_1) {
		target_1.getValue()="16774"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_entry_set_mode")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="dir"
		and not target_2.getValue()="dir2/"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="victim"
		and not target_3.getValue()="dir"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("assertion_make_dir")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4))
}

predicate func_5(Variable vae_36, ExprStmt target_21, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("archive_entry_set_mode")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_5.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="16749"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_5)
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vad_35, Variable vae_36, ExprStmt target_22, ExprStmt target_23, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_6.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_header")
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vae_36
		and target_6.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_header(ad, ae)"
		and target_6.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_6)
		and target_22.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Variable vad_35, AssignExpr target_24, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_finish_entry")
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_7.getExpr().(FunctionCall).getArgument(5) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_7)
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_24.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_8(Variable vae_36, ExprStmt target_23, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("assertion_assert")
		and target_8.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vae_36
		and target_8.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("archive_entry_new")
		and target_8.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand() instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="(ae = archive_entry_new()) != NULL"
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_8)
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_9(Variable vae_36, ExprStmt target_25, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("archive_entry_copy_pathname")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_9.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dir1"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_9)
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_10(Variable vae_36, ExprStmt target_26, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("archive_entry_free")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_10)
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_11(Variable vae_36, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("assertion_assert")
		and target_11.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_11.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vae_36
		and target_11.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("archive_entry_new")
		and target_11.getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand() instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="(ae = archive_entry_new()) != NULL"
		and target_11.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_11))
}

predicate func_12(Variable vae_36, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("archive_entry_copy_pathname")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_12.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dir2"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_12))
}

predicate func_15(Variable vae_36, Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(FunctionCall).getTarget().hasName("archive_entry_copy_symlink")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_15.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="file"
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_15))
}

predicate func_16(Variable vad_35, Variable vae_36, Variable vr_37, ExprStmt target_27, RelationalOperation target_28, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_16.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_16.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_37
		and target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("archive_write_header")
		and target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vae_36
		and target_16.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="r = archive_write_header(ad, ae)"
		and target_16.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_16)
		and target_27.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_28.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(4).(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_17(Variable vad_35, Variable vr_37, FunctionCall target_29, Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_37
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-20"
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_finish_entry")
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof StringLiteral
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_17)
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_29.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_19(Function func) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(FunctionCall).getTarget().hasName("assertion_is_symlink")
		and target_19.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_19.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_19.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_19.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_19.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_19 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_19))
}

predicate func_20(Function func) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(FunctionCall).getTarget().hasName("assertion_file_mode")
		and target_20.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_20.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_20.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_20.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(39)=target_20 or func.getEntryPoint().(BlockStmt).getStmt(39).getFollowingStmt()=target_20))
}

predicate func_21(Variable vae_36, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("archive_entry_copy_pathname")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_21.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_22(Variable vad_35, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_22.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_22.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_22.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_22.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_22.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_finish_entry")
		and target_22.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_22.getExpr().(FunctionCall).getArgument(5) instanceof StringLiteral
		and target_22.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
}

predicate func_23(Variable vae_36, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("archive_entry_set_mode")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_23.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="41471"
}

predicate func_24(Variable vad_35, Variable vae_36, Variable vr_37, AssignExpr target_24) {
		target_24.getLValue().(VariableAccess).getTarget()=vr_37
		and target_24.getRValue().(FunctionCall).getTarget().hasName("archive_write_header")
		and target_24.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_24.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vae_36
}

predicate func_25(Variable vae_36, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("archive_entry_set_size")
		and target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
		and target_25.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_26(Variable vae_36, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("archive_entry_free")
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_36
}

predicate func_27(Variable vad_35, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_27.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_27.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_27.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_27.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_27.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_finish_entry")
		and target_27.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vad_35
		and target_27.getExpr().(FunctionCall).getArgument(5) instanceof StringLiteral
		and target_27.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vad_35
}

predicate func_28(Variable vr_37, RelationalOperation target_28) {
		 (target_28 instanceof GEExpr or target_28 instanceof LEExpr)
		and target_28.getGreaterOperand().(VariableAccess).getTarget()=vr_37
		and target_28.getLesserOperand().(UnaryMinusExpr).getValue()="-20"
}

predicate func_29(Variable vad_35, FunctionCall target_29) {
		target_29.getTarget().hasName("archive_write_free")
		and target_29.getArgument(0).(VariableAccess).getTarget()=vad_35
}

from Function func, Variable vad_35, Variable vae_36, Variable vr_37, StringLiteral target_0, BitwiseOrExpr target_1, StringLiteral target_2, StringLiteral target_3, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, AssignExpr target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, RelationalOperation target_28, FunctionCall target_29
where
func_0(func, target_0)
and func_1(vae_36, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(func)
and not func_5(vae_36, target_21, func)
and not func_6(vad_35, vae_36, target_22, target_23, func)
and not func_7(vad_35, target_24, func)
and not func_8(vae_36, target_23, func)
and not func_9(vae_36, target_25, func)
and not func_10(vae_36, target_26, func)
and not func_11(vae_36, func)
and not func_12(vae_36, func)
and not func_15(vae_36, func)
and not func_16(vad_35, vae_36, vr_37, target_27, target_28, func)
and not func_17(vad_35, vr_37, target_29, func)
and not func_19(func)
and not func_20(func)
and func_21(vae_36, target_21)
and func_22(vad_35, target_22)
and func_23(vae_36, target_23)
and func_24(vad_35, vae_36, vr_37, target_24)
and func_25(vae_36, target_25)
and func_26(vae_36, target_26)
and func_27(vad_35, target_27)
and func_28(vr_37, target_28)
and func_29(vad_35, target_29)
and vad_35.getType().hasName("archive *")
and vae_36.getType().hasName("archive_entry *")
and vr_37.getType().hasName("int")
and vad_35.getParentScope+() = func
and vae_36.getParentScope+() = func
and vr_37.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
