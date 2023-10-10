/**
 * @name libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-_archive_write_disk_close
 * @id cpp/libarchive/8a1bd5c18e896f0411a991240ce0d772bb02c840/-archive-write-disk-close
 * @description libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-libarchive/archive_write_disk_posix.c-_archive_write_disk_close CVE-2021-31566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_2463, BlockStmt target_35, BitwiseOrExpr target_0) {
		target_0.getValue()="536871012"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_0.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_1(Variable vst_2464, Literal target_1) {
		target_1.getValue()="40960"
		and not target_1.getValue()="16384"
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_2464
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
}

predicate func_2(Variable vp_2463, BitwiseOrExpr target_2) {
		target_2.getValue()="655361"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_3(Variable vp_2463, EqualityOperation target_19) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("char *")
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_19.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(WhileStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_4.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getEnclosingFunction() = func)
}

/*predicate func_5(Function func) {
	exists(PostfixIncrExpr target_5 |
		target_5.getOperand().(VariableAccess).getType().hasName("char *")
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(Variable vp_2463, BitwiseAndExpr target_38) {
	exists(WhileStmt target_6 |
		target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_38.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_7(Function func) {
	exists(PointerDereferenceExpr target_7 |
		target_7.getOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_7.getOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
		and target_7.getEnclosingFunction() = func)
}

*/
/*predicate func_9(Function func) {
	exists(PostfixDecrExpr target_9 |
		target_9.getOperand().(VariableAccess).getType().hasName("char *")
		and target_9.getEnclosingFunction() = func)
}

*/
predicate func_10(Variable vp_2463, BlockStmt target_35, EqualityOperation target_39, BitwiseAndExpr target_26) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_10.getAnOperand() instanceof Literal
		and target_10.getParent().(IfStmt).getThen()=target_35
		and target_39.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_11(Variable vst_2464, GotoStmt target_40, AddressOfExpr target_41) {
	exists(LogicalOrExpr target_11 |
		target_11.getAnOperand() instanceof EqualityOperation
		and target_11.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_11.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_2464
		and target_11.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_11.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16384"
		and target_11.getParent().(IfStmt).getThen()=target_40
		and target_41.getOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(EqualityOperation target_42, Function func) {
	exists(GotoStmt target_12 |
		target_12.toString() = "goto ..."
		and target_12.getName() ="skip_fixup_entry"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_12.getEnclosingFunction() = func)
}

predicate func_14(Variable vp_2463, RelationalOperation target_43, NotExpr target_44, ExprStmt target_45) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_14.getExpr().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_14.getExpr().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_14.getExpr().(FunctionCall).getArgument(1).(BitwiseAndExpr).getRightOperand().(OctalLiteral).getValue()="4095"
		and target_14.getParent().(IfStmt).getCondition()=target_43
		and target_44.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_15(Variable vp_2463, ExprStmt target_46, ExprStmt target_45) {
	exists(BitwiseAndExpr target_15 |
		target_15.getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_15.getRightOperand().(OctalLiteral).getValue()="4095"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_46.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_16(Variable vp_2463, BlockStmt target_35, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="fixup"
		and target_16.getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_16.getParent().(BitwiseAndExpr).getRightOperand() instanceof BitwiseOrExpr
		and target_16.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_17(Variable vp_2463, BlockStmt target_47, BitwiseAndExpr target_17) {
		target_17.getLeftOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_17.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_17.getRightOperand().(Literal).getValue()="536870912"
		and target_17.getParent().(IfStmt).getThen()=target_47
}

predicate func_18(Variable vp_2463, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="mode"
		and target_18.getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_19(Variable vp_2463, Variable vst_2464, GotoStmt target_40, EqualityOperation target_19) {
		target_19.getAnOperand().(FunctionCall).getTarget().hasName("lstat")
		and target_19.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_19.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_19.getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vst_2464
		and target_19.getAnOperand().(Literal).getValue()="0"
		and target_19.getParent().(IfStmt).getThen()=target_40
}

predicate func_20(Variable vp_2463, Variable vfd_2465, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="mode"
		and target_20.getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fchmod")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_2465
}

predicate func_21(Variable vp_2463, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="mode"
		and target_21.getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_23(Variable vp_2463, VariableAccess target_23) {
		target_23.getTarget()=vp_2463
}

predicate func_24(Variable vp_2463, VariableAccess target_24) {
		target_24.getTarget()=vp_2463
}

predicate func_26(Variable vp_2463, BlockStmt target_35, BitwiseAndExpr target_26) {
		target_26.getLeftOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_26.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_26.getRightOperand() instanceof BitwiseOrExpr
		and target_26.getParent().(IfStmt).getThen()=target_35
}

predicate func_27(Function func, BitwiseOrExpr target_27) {
		target_27.getValue()="1"
		and target_27.getEnclosingFunction() = func
}

predicate func_29(Variable vp_2463, AssignAndExpr target_29) {
		target_29.getLValue().(PointerFieldAccess).getTarget().getName()="mode"
		and target_29.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_29.getRValue().(ComplementExpr).getValue()="4294905855"
}

predicate func_30(Variable vp_2463, AssignOrExpr target_30) {
		target_30.getLValue().(PointerFieldAccess).getTarget().getName()="mode"
		and target_30.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_30.getRValue().(Literal).getValue()="40960"
}

predicate func_31(Variable vp_2463, Variable vfd_2465, IfStmt target_31) {
		target_31.getCondition() instanceof BitwiseAndExpr
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfd_2465
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fchmod")
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_2465
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="40960"
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_31.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
}

/*predicate func_32(Variable vp_2463, RelationalOperation target_43, IfStmt target_32) {
		target_32.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_32.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_32.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_32.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="40960"
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_32.getParent().(IfStmt).getCondition()=target_43
}

*/
predicate func_35(Variable vp_2463, Variable vfd_2465, BlockStmt target_35) {
		target_35.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfd_2465
		and target_35.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("open")
		and target_35.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_35.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_35.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof BitwiseOrExpr
}

predicate func_38(Variable vp_2463, BitwiseAndExpr target_38) {
		target_38.getLeftOperand().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_38.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_38.getRightOperand().(Literal).getValue()="4"
}

predicate func_39(Variable vp_2463, EqualityOperation target_39) {
		target_39.getAnOperand().(VariableAccess).getTarget()=vp_2463
		and target_39.getAnOperand().(Literal).getValue()="0"
}

predicate func_40(GotoStmt target_40) {
		target_40.toString() = "goto ..."
		and target_40.getName() ="skip_fixup_entry"
}

predicate func_41(Variable vst_2464, AddressOfExpr target_41) {
		target_41.getOperand().(VariableAccess).getTarget()=vst_2464
}

predicate func_42(Variable vst_2464, EqualityOperation target_42) {
		target_42.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_42.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_2464
		and target_42.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_42.getAnOperand() instanceof Literal
}

predicate func_43(Variable vfd_2465, RelationalOperation target_43) {
		 (target_43 instanceof GEExpr or target_43 instanceof LEExpr)
		and target_43.getGreaterOperand().(VariableAccess).getTarget()=vfd_2465
		and target_43.getLesserOperand().(Literal).getValue()="0"
}

predicate func_44(Variable vp_2463, NotExpr target_44) {
		target_44.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_44.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_44.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_44.getOperand().(EqualityOperation).getAnOperand() instanceof Literal
}

predicate func_45(Variable vp_2463, ExprStmt target_45) {
		target_45.getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_45.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_45.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_45.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_45.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_46(Variable vp_2463, Variable vfd_2465, ExprStmt target_46) {
		target_46.getExpr().(FunctionCall).getTarget().hasName("fchmod")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_2465
		and target_46.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_46.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
}

predicate func_47(Variable vp_2463, Variable vfd_2465, BlockStmt target_47) {
		target_47.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfd_2465
		and target_47.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_47.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fchmod")
		and target_47.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_2465
		and target_47.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mode"
		and target_47.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_2463
		and target_47.getStmt(0).(IfStmt).getElse() instanceof IfStmt
}

from Function func, Variable vp_2463, Variable vst_2464, Variable vfd_2465, BitwiseOrExpr target_0, Literal target_1, BitwiseOrExpr target_2, PointerFieldAccess target_16, BitwiseAndExpr target_17, PointerFieldAccess target_18, EqualityOperation target_19, PointerFieldAccess target_20, PointerFieldAccess target_21, VariableAccess target_23, VariableAccess target_24, BitwiseAndExpr target_26, BitwiseOrExpr target_27, AssignAndExpr target_29, AssignOrExpr target_30, IfStmt target_31, BlockStmt target_35, BitwiseAndExpr target_38, EqualityOperation target_39, GotoStmt target_40, AddressOfExpr target_41, EqualityOperation target_42, RelationalOperation target_43, NotExpr target_44, ExprStmt target_45, ExprStmt target_46, BlockStmt target_47
where
func_0(vp_2463, target_35, target_0)
and func_1(vst_2464, target_1)
and func_2(vp_2463, target_2)
and not func_3(vp_2463, target_19)
and not func_4(func)
and not func_6(vp_2463, target_38)
and not func_10(vp_2463, target_35, target_39, target_26)
and not func_11(vst_2464, target_40, target_41)
and not func_12(target_42, func)
and not func_14(vp_2463, target_43, target_44, target_45)
and func_16(vp_2463, target_35, target_16)
and func_17(vp_2463, target_47, target_17)
and func_18(vp_2463, target_18)
and func_19(vp_2463, vst_2464, target_40, target_19)
and func_20(vp_2463, vfd_2465, target_20)
and func_21(vp_2463, target_21)
and func_23(vp_2463, target_23)
and func_24(vp_2463, target_24)
and func_26(vp_2463, target_35, target_26)
and func_27(func, target_27)
and func_29(vp_2463, target_29)
and func_30(vp_2463, target_30)
and func_31(vp_2463, vfd_2465, target_31)
and func_35(vp_2463, vfd_2465, target_35)
and func_38(vp_2463, target_38)
and func_39(vp_2463, target_39)
and func_40(target_40)
and func_41(vst_2464, target_41)
and func_42(vst_2464, target_42)
and func_43(vfd_2465, target_43)
and func_44(vp_2463, target_44)
and func_45(vp_2463, target_45)
and func_46(vp_2463, vfd_2465, target_46)
and func_47(vp_2463, vfd_2465, target_47)
and vp_2463.getType().hasName("fixup_entry *")
and vst_2464.getType().hasName("stat")
and vfd_2465.getType().hasName("int")
and vp_2463.getParentScope+() = func
and vst_2464.getParentScope+() = func
and vfd_2465.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
