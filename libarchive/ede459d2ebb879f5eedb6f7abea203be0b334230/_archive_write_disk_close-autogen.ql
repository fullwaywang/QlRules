/**
 * @name libarchive-ede459d2ebb879f5eedb6f7abea203be0b334230-_archive_write_disk_close
 * @id cpp/libarchive/ede459d2ebb879f5eedb6f7abea203be0b334230/-archive-write-disk-close
 * @description libarchive-ede459d2ebb879f5eedb6f7abea203be0b334230-libarchive/archive_write_disk_posix.c-_archive_write_disk_close CVE-2021-31566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, BitwiseOrExpr target_0) {
		target_0.getValue()="196608"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="524288"
		and not target_1.getValue()="65536"
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getArgument(1) instanceof BitwiseOrExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="61440"
		and not target_2.getValue()="16384"
		and target_2.getParent().(BitwiseAndExpr).getParent().(EQExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_5(Variable vp_2463) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="filetype"
		and target_5.getQualifier().(VariableAccess).getTarget()=vp_2463)
}

predicate func_6(EqualityOperation target_14, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="65536"
		and target_6.getParent().(IfStmt).getCondition()=target_14
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vp_2463, Variable vfd_2466, EqualityOperation target_20, ExprStmt target_21, EqualityOperation target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfd_2466
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vp_2463, Variable vfd_2466, EqualityOperation target_20, EqualityOperation target_14) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filetype"
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16384"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfd_2466
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("fstat")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("la_verify_filetype")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="skip_fixup_entry"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("la_verify_filetype")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="skip_fixup_entry"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_10(Variable vp_2463, BlockStmt target_23) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="filetype"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_10.getAnOperand().(Literal).getValue()="16384"
		and target_10.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_10.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_10.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_23)
}

*/
/*predicate func_11(Variable vp_2463, Variable vst_2464, Variable vfd_2466, BlockStmt target_23, ExprStmt target_25, AddressOfExpr target_27, EqualityOperation target_14, ExprStmt target_28) {
	exists(LogicalAndExpr target_11 |
		target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfd_2466
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("fstat")
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_2466
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vst_2464
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("la_verify_filetype")
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="filetype"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen()=target_23
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getOperand().(VariableAccess).getLocation())
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
/*predicate func_12(Variable vp_2463, Variable vst_2464, LogicalOrExpr target_29, BitwiseAndExpr target_30) {
	exists(IfStmt target_12 |
		target_12.getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("la_verify_filetype")
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_2464
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="filetype"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="skip_fixup_entry"
		and target_12.getParent().(IfStmt).getCondition()=target_29
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_30.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Variable vp_2463, Variable vst_2464, BlockStmt target_23, EqualityOperation target_13) {
		target_13.getAnOperand().(FunctionCall).getTarget().hasName("lstat")
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_13.getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vst_2464
		and target_13.getAnOperand().(Literal).getValue()="0"
		and target_13.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_13.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_23
}

predicate func_14(Variable vfd_2466, BlockStmt target_31, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vfd_2466
		and target_14.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_14.getParent().(IfStmt).getThen()=target_31
}

predicate func_15(Variable vst_2464, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="st_mode"
		and target_15.getQualifier().(VariableAccess).getTarget()=vst_2464
}

predicate func_16(Variable vp_2463, Variable vfd_2466, VariableAccess target_16) {
		target_16.getTarget()=vfd_2466
		and target_16.getParent().(AssignExpr).getLValue() = target_16
		and target_16.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_16.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_16.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_16.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof BitwiseOrExpr
}

predicate func_17(Variable vp_2463, BitwiseOrExpr target_17) {
		target_17.getValue()="720896"
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_18(BlockStmt target_23, Function func, NotExpr target_18) {
		target_18.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand() instanceof ValueFieldAccess
		and target_18.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_18.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16384"
		and target_18.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_18.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_23
		and target_18.getEnclosingFunction() = func
}

/*predicate func_19(Function func, BitwiseAndExpr target_19) {
		target_19.getLeftOperand() instanceof ValueFieldAccess
		and target_19.getRightOperand() instanceof Literal
		and target_19.getEnclosingFunction() = func
}

*/
predicate func_20(Variable vp_2463, EqualityOperation target_20) {
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_20.getAnOperand().(Literal).getValue()="0"
}

predicate func_21(Variable vfd_2466, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfd_2466
		and target_21.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
}

predicate func_23(BlockStmt target_23) {
		target_23.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_23.getStmt(0).(GotoStmt).getName() ="skip_fixup_entry"
}

predicate func_25(Variable vp_2463, Variable vfd_2466, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfd_2466
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof BitwiseOrExpr
}

predicate func_27(Variable vst_2464, AddressOfExpr target_27) {
		target_27.getOperand().(VariableAccess).getTarget()=vst_2464
}

predicate func_28(Variable vp_2463, Variable vfd_2466, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("set_times")
		and target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfd_2466
		and target_28.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="mode"
		and target_28.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="name"
		and target_28.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="atime"
		and target_28.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="atime_nanos"
		and target_28.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="birthtime"
		and target_28.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="birthtime_nanos"
		and target_28.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="mtime"
		and target_28.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="mtime_nanos"
		and target_28.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="ctime"
		and target_28.getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_28.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getTarget().getName()="ctime_nanos"
		and target_28.getExpr().(FunctionCall).getArgument(11).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_29(LogicalOrExpr target_29) {
		target_29.getAnOperand() instanceof EqualityOperation
		and target_29.getAnOperand() instanceof NotExpr
}

predicate func_30(Variable vp_2463, BitwiseAndExpr target_30) {
		target_30.getLeftOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_30.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_30.getRightOperand().(Literal).getValue()="4"
}

predicate func_31(BlockStmt target_31) {
		target_31.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_31.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_31.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_31.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="skip_fixup_entry"
}

from Function func, Variable vp_2463, Variable vst_2464, Variable vfd_2466, BitwiseOrExpr target_0, Literal target_1, Literal target_2, EqualityOperation target_13, EqualityOperation target_14, ValueFieldAccess target_15, VariableAccess target_16, BitwiseOrExpr target_17, NotExpr target_18, EqualityOperation target_20, ExprStmt target_21, BlockStmt target_23, ExprStmt target_25, AddressOfExpr target_27, ExprStmt target_28, LogicalOrExpr target_29, BitwiseAndExpr target_30, BlockStmt target_31
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_5(vp_2463)
and not func_6(target_14, func)
and not func_7(vp_2463, vfd_2466, target_20, target_21, target_14)
and not func_9(vp_2463, vfd_2466, target_20, target_14)
and func_13(vp_2463, vst_2464, target_23, target_13)
and func_14(vfd_2466, target_31, target_14)
and func_15(vst_2464, target_15)
and func_16(vp_2463, vfd_2466, target_16)
and func_17(vp_2463, target_17)
and func_18(target_23, func, target_18)
and func_20(vp_2463, target_20)
and func_21(vfd_2466, target_21)
and func_23(target_23)
and func_25(vp_2463, vfd_2466, target_25)
and func_27(vst_2464, target_27)
and func_28(vp_2463, vfd_2466, target_28)
and func_29(target_29)
and func_30(vp_2463, target_30)
and func_31(target_31)
and vp_2463.getType().hasName("fixup_entry *")
and vst_2464.getType().hasName("stat")
and vfd_2466.getType().hasName("int")
and vp_2463.getParentScope+() = func
and vst_2464.getParentScope+() = func
and vfd_2466.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
