/**
 * @name vim-57df9e8a9f9ae1aafdde9b86b10ad907627a87dc-block_insert
 * @id cpp/vim/57df9e8a9f9ae1aafdde9b86b10ad907627a87dc/block-insert
 * @description vim-57df9e8a9f9ae1aafdde9b86b10ad907627a87dc-src/ops.c-block_insert CVE-2022-0318
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voap_477, Parameter vbdp_480, Variable vlnum_489, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("block_prep")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_477
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbdp_480
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlnum_489
		and target_0.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_1(Parameter vb_insert_479, Parameter vbdp_480, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_short"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vb_insert_479
		and target_1.getThen().(ContinueStmt).toString() = "continue;"
}

predicate func_2(Variable voldp_488, Variable vlnum_489, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voldp_488
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ml_get")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlnum_489
}

predicate func_3(Parameter vb_insert_479, Parameter vbdp_480, Variable vts_val_482, Variable vcount_483, Variable vspaces_484, Variable voffset_485, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vb_insert_479
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vts_val_482
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="start_char_vcols"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspaces_484
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="startspaces"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vspaces_484
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_483
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vts_val_482
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="textcol"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vts_val_482
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="end_char_vcols"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_short"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspaces_484
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vspaces_484
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_MAX"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_483
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vspaces_484
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_485
}

predicate func_4(Variable vmb_head_off, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vmb_head_off
}

predicate func_5(Variable vspaces_484, IfStmt target_5) {
		target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vspaces_484
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspaces_484
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Variable vcount_483, Variable vnewp_488, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewp_488
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_483
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vnewp_488, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewp_488
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getThen().(ContinueStmt).toString() = "continue;"
}

predicate func_8(Variable voffset_485, Variable vnewp_488, Variable voldp_488, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewp_488
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voldp_488
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_485
}

predicate func_9(Variable voffset_485, Variable voldp_488, ExprStmt target_9) {
		target_9.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=voldp_488
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=voffset_485
}

predicate func_10(Variable vspaces_484, Variable voffset_485, Variable vnewp_488, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnewp_488
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_485
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vspaces_484
}

predicate func_11(Variable vspaces_484, Variable voffset_485, Variable vstartcol_486, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstartcol_486
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_485
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vspaces_484
}

predicate func_12(Parameter vs_478, Variable vstartcol_486, Variable vs_len_487, Variable vnewp_488, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnewp_488
		and target_12.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vstartcol_486
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_478
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_len_487
}

predicate func_13(Variable voffset_485, Variable vs_len_487, ExprStmt target_13) {
		target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_13.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vs_len_487
}

predicate func_14(Parameter vbdp_480, Variable vcount_483, Variable vspaces_484, Variable voldp_488, IfStmt target_14) {
		target_14.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vspaces_484
		and target_14.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_14.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_short"
		and target_14.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbdp_480
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voldp_488
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="9"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voldp_488
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcount_483
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_483
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vspaces_484
}

predicate func_15(Variable vcount_483, Variable vspaces_484, Variable voffset_485, IfStmt target_15) {
		target_15.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vspaces_484
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_15.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_15.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcount_483
}

predicate func_16(Variable voffset_485, Variable vnewp_488, Variable voldp_488, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_16.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnewp_488
		and target_16.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_485
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voldp_488
		and target_16.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_16.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voldp_488
		and target_16.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_17(Variable vnewp_488, Variable vlnum_489, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("ml_replace")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlnum_489
		and target_17.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnewp_488
		and target_17.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_18(Parameter vb_insert_479, Variable vstartcol_486, Variable vs_len_487, Variable vlnum_489, IfStmt target_18) {
		target_18.getCondition().(VariableAccess).getTarget()=vb_insert_479
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("inserted_bytes")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlnum_489
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstartcol_486
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_len_487
}

predicate func_19(Parameter voap_477, Variable voffset_485, Variable vlnum_489, Variable vcurbuf, IfStmt target_19) {
		target_19.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlnum_489
		and target_19.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_19.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_19.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_477
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_477
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffset_485
}

predicate func_20(Variable voffset_485, Variable voldp_488, Variable vmb_head_off, ExprCall target_20) {
		target_20.getExpr().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmb_head_off
		and target_20.getArgument(0).(VariableAccess).getTarget()=voldp_488
		and target_20.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voldp_488
		and target_20.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_485
}

predicate func_21(LogicalAndExpr target_29, Function func, DeclStmt target_21) {
		target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_29
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Parameter vb_insert_479, Variable vcount_483, Variable vspaces_484, Variable voffset_485, Variable voldp_488, Variable voff_533, LogicalAndExpr target_29, IfStmt target_22) {
		target_22.getCondition().(VariableAccess).getTarget()=vb_insert_479
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_533
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getExpr() instanceof PointerDereferenceExpr
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget()=voldp_488
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vspaces_484
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vspaces_484
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vcount_483
		and target_22.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_22.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_533
		and target_22.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and target_22.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_22.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_29
}

/*predicate func_23(Variable vspaces_484, Variable voffset_485, Variable voldp_488, Variable voff_533, AssignExpr target_23) {
		target_23.getLValue().(VariableAccess).getTarget()=voff_533
		and target_23.getRValue().(ExprCall).getExpr() instanceof PointerDereferenceExpr
		and target_23.getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget()=voldp_488
		and target_23.getRValue().(ExprCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voldp_488
		and target_23.getRValue().(ExprCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_485
		and target_23.getRValue().(ExprCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vspaces_484
}

*/
/*predicate func_24(Variable vspaces_484, Variable voff_533, VariableAccess target_30, ExprStmt target_24) {
		target_24.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vspaces_484
		and target_24.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
}

*/
/*predicate func_25(Variable vcount_483, Variable voff_533, VariableAccess target_30, ExprStmt target_25) {
		target_25.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vcount_483
		and target_25.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
}

*/
predicate func_26(Variable voff_533, VariableAccess target_30, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_533
		and target_26.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
}

/*predicate func_27(Variable voffset_485, Variable voff_533, VariableAccess target_30, ExprStmt target_27) {
		target_27.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_27.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_533
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
}

*/
/*predicate func_28(Variable voffset_485, Variable voff_533, PointerArithmeticOperation target_31, ExprStmt target_8, ExprStmt target_26, VariableAccess target_28) {
		target_28.getTarget()=voff_533
		and target_28.getParent().(AssignSubExpr).getRValue() = target_28
		and target_28.getParent().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_31.getAnOperand().(VariableAccess).getLocation().isBefore(target_28.getParent().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_28.getParent().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_28.getLocation())
}

*/
predicate func_29(Variable vspaces_484, LogicalAndExpr target_29) {
		target_29.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vspaces_484
		and target_29.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_30(Parameter vb_insert_479, VariableAccess target_30) {
		target_30.getTarget()=vb_insert_479
}

predicate func_31(Variable voffset_485, Variable voldp_488, PointerArithmeticOperation target_31) {
		target_31.getAnOperand().(VariableAccess).getTarget()=voldp_488
		and target_31.getAnOperand().(VariableAccess).getTarget()=voffset_485
}

from Function func, Parameter voap_477, Parameter vs_478, Parameter vb_insert_479, Parameter vbdp_480, Variable vts_val_482, Variable vcount_483, Variable vspaces_484, Variable voffset_485, Variable vstartcol_486, Variable vs_len_487, Variable vnewp_488, Variable voldp_488, Variable vlnum_489, Variable voff_533, Variable vmb_head_off, Variable vcurbuf, ExprStmt target_0, IfStmt target_1, ExprStmt target_2, IfStmt target_3, PointerDereferenceExpr target_4, IfStmt target_5, ExprStmt target_6, IfStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, IfStmt target_14, IfStmt target_15, ExprStmt target_16, ExprStmt target_17, IfStmt target_18, IfStmt target_19, ExprCall target_20, DeclStmt target_21, IfStmt target_22, ExprStmt target_26, LogicalAndExpr target_29, VariableAccess target_30, PointerArithmeticOperation target_31
where
func_0(voap_477, vbdp_480, vlnum_489, target_0)
and func_1(vb_insert_479, vbdp_480, target_1)
and func_2(voldp_488, vlnum_489, target_2)
and func_3(vb_insert_479, vbdp_480, vts_val_482, vcount_483, vspaces_484, voffset_485, target_3)
and func_4(vmb_head_off, target_4)
and func_5(vspaces_484, target_5)
and func_6(vcount_483, vnewp_488, target_6)
and func_7(vnewp_488, target_7)
and func_8(voffset_485, vnewp_488, voldp_488, target_8)
and func_9(voffset_485, voldp_488, target_9)
and func_10(vspaces_484, voffset_485, vnewp_488, target_10)
and func_11(vspaces_484, voffset_485, vstartcol_486, target_11)
and func_12(vs_478, vstartcol_486, vs_len_487, vnewp_488, target_12)
and func_13(voffset_485, vs_len_487, target_13)
and func_14(vbdp_480, vcount_483, vspaces_484, voldp_488, target_14)
and func_15(vcount_483, vspaces_484, voffset_485, target_15)
and func_16(voffset_485, vnewp_488, voldp_488, target_16)
and func_17(vnewp_488, vlnum_489, target_17)
and func_18(vb_insert_479, vstartcol_486, vs_len_487, vlnum_489, target_18)
and func_19(voap_477, voffset_485, vlnum_489, vcurbuf, target_19)
and func_20(voffset_485, voldp_488, vmb_head_off, target_20)
and func_21(target_29, func, target_21)
and func_22(vb_insert_479, vcount_483, vspaces_484, voffset_485, voldp_488, voff_533, target_29, target_22)
and func_26(voff_533, target_30, target_26)
and func_29(vspaces_484, target_29)
and func_30(vb_insert_479, target_30)
and func_31(voffset_485, voldp_488, target_31)
and voap_477.getType().hasName("oparg_T *")
and vs_478.getType().hasName("char_u *")
and vb_insert_479.getType().hasName("int")
and vbdp_480.getType().hasName("block_def *")
and vts_val_482.getType().hasName("int")
and vcount_483.getType().hasName("int")
and vspaces_484.getType().hasName("int")
and voffset_485.getType().hasName("colnr_T")
and vstartcol_486.getType().hasName("colnr_T")
and vs_len_487.getType().hasName("unsigned int")
and vnewp_488.getType().hasName("char_u *")
and voldp_488.getType().hasName("char_u *")
and vlnum_489.getType().hasName("linenr_T")
and voff_533.getType().hasName("int")
and vmb_head_off.getType().hasName("..(*)(..)")
and vcurbuf.getType().hasName("buf_T *")
and voap_477.getParentScope+() = func
and vs_478.getParentScope+() = func
and vb_insert_479.getParentScope+() = func
and vbdp_480.getParentScope+() = func
and vts_val_482.getParentScope+() = func
and vcount_483.getParentScope+() = func
and vspaces_484.getParentScope+() = func
and voffset_485.getParentScope+() = func
and vstartcol_486.getParentScope+() = func
and vs_len_487.getParentScope+() = func
and vnewp_488.getParentScope+() = func
and voldp_488.getParentScope+() = func
and vlnum_489.getParentScope+() = func
and voff_533.getParentScope+() = func
and not vmb_head_off.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
