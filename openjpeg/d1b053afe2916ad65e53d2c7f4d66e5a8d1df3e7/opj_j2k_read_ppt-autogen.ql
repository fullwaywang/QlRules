/**
 * @name openjpeg-d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7-opj_j2k_read_ppt
 * @id cpp/openjpeg/d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7/opj-j2k-read-ppt
 * @description openjpeg-d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7-src/lib/openjp2/j2k.c-opj_j2k_read_ppt CVE-2015-1239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_header_size_3875, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp_header_size_3875
}

predicate func_1(Variable vl_tcp_3880, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="ppt_data_size"
		and target_1.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

/*predicate func_2(Variable vl_tcp_3880, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ppt_len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

*/
predicate func_3(Parameter vp_header_size_3875, Variable vl_tcp_3880, VariableAccess target_3) {
		target_3.getTarget()=vp_header_size_3875
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_4(Variable vl_tcp_3880, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="ppt_len"
		and target_4.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_5(Variable vl_tcp_3880, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="ppt_len"
		and target_5.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_6(Variable vl_tcp_3880, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="ppt_len"
		and target_6.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_7(Variable vl_tcp_3880, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="ppt_data_size"
		and target_7.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_8(Function func, SizeofTypeOperator target_8) {
		target_8.getType() instanceof LongType
		and target_8.getValue()="1"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vp_header_size_3875, Variable vl_tcp_3880, VariableAccess target_9) {
		target_9.getTarget()=vp_header_size_3875
		and target_9.getParent().(AssignAddExpr).getRValue() = target_9
		and target_9.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_9.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_10(Variable vl_tcp_3880, ExprStmt target_71, ExprStmt target_72) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="ppt_markers"
		and target_10.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_71.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getQualifier().(VariableAccess).getLocation())
		and target_10.getQualifier().(VariableAccess).getLocation().isBefore(target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Variable vl_tcp_3880) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_12.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_12.getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_12.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_12.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_12.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="16")
}

predicate func_13(Variable vl_tcp_3880, ExprStmt target_72) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="ppt_markers"
		and target_13.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getQualifier().(VariableAccess).getLocation()))
}

predicate func_14(Variable vl_tcp_3880, Variable vl_Z_ppt_3881, EqualityOperation target_75, ExprStmt target_72) {
	exists(IfStmt target_14 |
		target_14.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_14.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("opj_ppt *")
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="16"
		and target_14.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("opj_ppt *")
		and target_14.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_14.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_14.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("opj_ppt *")
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="16"
		and target_14.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_14.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_14.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_14.getParent().(IfStmt).getCondition()=target_75
		and target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_15(Variable vl_tcp_3880, EqualityOperation target_77) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(VariableAccess).getType().hasName("opj_ppt *")
		and target_15.getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_15.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_15.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_15.getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_15.getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_15.getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="16"
		and target_77.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_16(Variable vl_tcp_3880, EqualityOperation target_77) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="ppt_markers"
		and target_16.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_77.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_17(Variable vl_tcp_3880) {
	exists(MulExpr target_17 |
		target_17.getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_17.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_17.getRightOperand().(SizeofTypeOperator).getValue()="16"
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880)
}

*/
/*predicate func_18(BlockStmt target_78, Function func) {
	exists(EqualityOperation target_18 |
		target_18.getAnOperand().(VariableAccess).getType().hasName("opj_ppt *")
		and target_18.getAnOperand() instanceof Literal
		and target_18.getParent().(IfStmt).getThen()=target_78
		and target_18.getEnclosingFunction() = func)
}

*/
/*predicate func_19(Variable vl_tcp_3880) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_19.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_19.getRValue().(VariableAccess).getType().hasName("opj_ppt *"))
}

*/
/*predicate func_20(Parameter vp_header_size_3875, Variable vl_tcp_3880) {
	exists(PointerArithmeticOperation target_20 |
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_header_size_3875)
}

*/
/*predicate func_21(Parameter vp_header_size_3875, Variable vl_tcp_3880, PointerArithmeticOperation target_67, PointerArithmeticOperation target_69) {
	exists(MulExpr target_21 |
		target_21.getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_21.getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ppt_markers_count"
		and target_21.getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_21.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_21.getRightOperand().(SizeofTypeOperator).getValue()="16"
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_21.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_header_size_3875
		and target_67.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_69.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_23(Parameter vp_manager_3876, Variable vl_tcp_3880, Variable vl_Z_ppt_3881, ExprStmt target_83, Function func) {
	exists(IfStmt target_23 |
		target_23.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="m_data"
		and target_23.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_23.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_23.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_23.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Zppt %u already read\n"
		and target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_23.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_23 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_23)
		and target_83.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_23.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_24(Parameter vp_manager_3876, Variable vl_Z_ppt_3881, ExprStmt target_83) {
	exists(FunctionCall target_24 |
		target_24.getTarget().hasName("opj_event_msg")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_24.getArgument(1).(Literal).getValue()="1"
		and target_24.getArgument(2).(StringLiteral).getValue()="Zppt %u already read\n"
		and target_24.getArgument(3).(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_83.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_24.getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_25(Variable vl_tcp_3880, Variable vl_Z_ppt_3881, ExprStmt target_87, EqualityOperation target_75) {
	exists(ValueFieldAccess target_25 |
		target_25.getTarget().getName()="m_data"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_75.getAnOperand().(VariableAccess).getLocation().isBefore(target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_26(Parameter vp_header_size_3875, ExprStmt target_66, ExprStmt target_70) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("malloc")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vp_header_size_3875
		and target_66.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_26.getArgument(0).(VariableAccess).getLocation())
		and target_26.getArgument(0).(VariableAccess).getLocation().isBefore(target_70.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_27(Parameter vp_manager_3876, Variable vl_tcp_3880, Variable vl_Z_ppt_3881, ExprStmt target_31, Function func) {
	exists(IfStmt target_27 |
		target_27.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="m_data"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_27.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_27.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_27.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to read PPT marker\n"
		and target_27.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_27 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_27)
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_28(Parameter vp_manager_3876, ExprStmt target_31) {
	exists(FunctionCall target_28 |
		target_28.getTarget().hasName("opj_event_msg")
		and target_28.getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_28.getArgument(1).(Literal).getValue()="1"
		and target_28.getArgument(2).(StringLiteral).getValue()="Not enough memory to read PPT marker\n"
		and target_28.getArgument(0).(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_29(Variable vl_tcp_3880, Variable vl_Z_ppt_3881, ExprStmt target_87) {
	exists(ValueFieldAccess target_29 |
		target_29.getTarget().getName()="m_data_size"
		and target_29.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_29.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_29.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_30(Variable vl_tcp_3880, Variable vl_Z_ppt_3881) {
	exists(ValueFieldAccess target_30 |
		target_30.getTarget().getName()="m_data"
		and target_30.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ppt_markers"
		and target_30.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_30.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vl_Z_ppt_3881)
}

predicate func_31(Parameter vp_manager_3876, NotExpr target_60, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_31.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_31.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to read PPT marker\n"
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_60
}

predicate func_32(NotExpr target_60, Function func, ReturnStmt target_32) {
		target_32.getExpr().(Literal).getValue()="0"
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_60
		and target_32.getEnclosingFunction() = func
}

predicate func_33(Variable vl_Z_ppt_3881, BlockStmt target_92, VariableAccess target_33) {
		target_33.getTarget()=vl_Z_ppt_3881
		and target_33.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_33.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_92
}

predicate func_34(Variable vl_tcp_3880, VariableAccess target_34) {
		target_34.getTarget()=vl_tcp_3880
}

predicate func_35(Variable vl_tcp_3880, VariableAccess target_35) {
		target_35.getTarget()=vl_tcp_3880
}

predicate func_36(Variable vl_tcp_3880, VariableAccess target_36) {
		target_36.getTarget()=vl_tcp_3880
}

predicate func_37(Variable vl_tcp_3880, VariableAccess target_37) {
		target_37.getTarget()=vl_tcp_3880
}

predicate func_38(Variable vl_tcp_3880, VariableAccess target_38) {
		target_38.getTarget()=vl_tcp_3880
}

predicate func_39(Parameter vp_header_size_3875, Variable vl_tcp_3880, VariableAccess target_39) {
		target_39.getTarget()=vp_header_size_3875
		and target_39.getParent().(AssignAddExpr).getRValue() = target_39
		and target_39.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_39.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_40(Variable vl_tcp_3880, VariableAccess target_40) {
		target_40.getTarget()=vl_tcp_3880
}

predicate func_41(Variable vl_tcp_3880, VariableAccess target_41) {
		target_41.getTarget()=vl_tcp_3880
}

predicate func_42(Variable vl_tcp_3880, VariableAccess target_42) {
		target_42.getTarget()=vl_tcp_3880
}

predicate func_43(Variable vl_tcp_3880, VariableAccess target_43) {
		target_43.getTarget()=vl_tcp_3880
}

predicate func_44(Variable vl_tcp_3880, VariableAccess target_44) {
		target_44.getTarget()=vl_tcp_3880
}

predicate func_45(Variable vl_tcp_3880, VariableAccess target_45) {
		target_45.getTarget()=vl_tcp_3880
}

predicate func_46(Parameter vp_header_size_3875, VariableAccess target_46) {
		target_46.getTarget()=vp_header_size_3875
		and target_46.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_46.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_46.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_50(Parameter vp_header_data_3874, Parameter vp_header_size_3875, VariableAccess target_50) {
		target_50.getTarget()=vp_header_size_3875
		and target_50.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_50.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_50.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_header_data_3874
}

predicate func_51(Variable vl_tcp_3880, ExprStmt target_71, ExprStmt target_72, FunctionCall target_51) {
		target_51.getTarget().hasName("free")
		and target_51.getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_51.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_71.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_51.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_51.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_52(Variable vl_tcp_3880, PointerFieldAccess target_52) {
		target_52.getTarget().getName()="ppt_buffer"
		and target_52.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_53(Variable vl_tcp_3880, ExprStmt target_72, PointerFieldAccess target_53) {
		target_53.getTarget().getName()="ppt_buffer"
		and target_53.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_53.getQualifier().(VariableAccess).getLocation())
}

predicate func_55(Variable vl_tcp_3880, EqualityOperation target_77, AssignExpr target_55) {
		target_55.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_data"
		and target_55.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_55.getRValue().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_55.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_77.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_55.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_57(Parameter vp_header_size_3875, Variable vl_tcp_3880, AssignAddExpr target_57) {
		target_57.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_57.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_57.getRValue().(VariableAccess).getTarget()=vp_header_size_3875
}

predicate func_58(Variable vl_tcp_3880, Variable vnew_ppt_buffer_3924, AssignExpr target_58) {
		target_58.getLValue().(VariableAccess).getTarget()=vnew_ppt_buffer_3924
		and target_58.getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_58.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_58.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_58.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_58.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

/*predicate func_59(Variable vl_tcp_3880, PointerFieldAccess target_59) {
		target_59.getTarget().getName()="ppt_buffer"
		and target_59.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

*/
predicate func_60(Variable vnew_ppt_buffer_3924, BlockStmt target_78, NotExpr target_60) {
		target_60.getOperand().(VariableAccess).getTarget()=vnew_ppt_buffer_3924
		and target_60.getParent().(IfStmt).getThen()=target_78
}

predicate func_61(Variable vl_tcp_3880, FunctionCall target_61) {
		target_61.getTarget().hasName("free")
		and target_61.getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_61.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_62(Variable vl_tcp_3880, AssignExpr target_62) {
		target_62.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_62.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_62.getRValue() instanceof Literal
}

predicate func_63(Variable vl_tcp_3880, PointerFieldAccess target_63) {
		target_63.getTarget().getName()="ppt_len"
		and target_63.getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_64(Variable vl_tcp_3880, Variable vnew_ppt_buffer_3924, AssignExpr target_64) {
		target_64.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_64.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_64.getRValue().(VariableAccess).getTarget()=vnew_ppt_buffer_3924
}

predicate func_65(Variable vl_tcp_3880, PointerArithmeticOperation target_67, AssignExpr target_65) {
		target_65.getLValue().(PointerFieldAccess).getTarget().getName()="ppt_data"
		and target_65.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_65.getRValue().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_65.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_65.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_67.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_66(Parameter vp_header_size_3875, Variable vl_tcp_3880, EqualityOperation target_75, ExprStmt target_66) {
		target_66.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_66.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_66.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_66.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_66.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_66.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_66.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_header_size_3875
		and target_66.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_75
}

predicate func_67(Variable vl_tcp_3880, PointerArithmeticOperation target_67) {
		target_67.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_67.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_67.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_67.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_68(Parameter vp_header_data_3874, Parameter vp_header_size_3875, Variable vl_tcp_3880, ExprStmt target_68) {
		target_68.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_68.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_68.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_68.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_68.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_68.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_header_data_3874
		and target_68.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_header_size_3875
}

predicate func_69(Variable vl_tcp_3880, PointerArithmeticOperation target_69) {
		target_69.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_69.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_69.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_69.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
}

predicate func_70(Parameter vp_header_size_3875, Variable vl_tcp_3880, ExprStmt target_70) {
		target_70.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_70.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_70.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vp_header_size_3875
}

predicate func_71(Parameter vp_header_size_3875, Variable vl_tcp_3880, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_71.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_71.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_header_size_3875
}

predicate func_72(Variable vl_tcp_3880, ExprStmt target_72) {
		target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_72.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_72.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_72.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_72.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_72.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofTypeOperator
}

predicate func_75(Variable vl_Z_ppt_3881, EqualityOperation target_75) {
		target_75.getAnOperand().(VariableAccess).getTarget()=vl_Z_ppt_3881
		and target_75.getAnOperand().(Literal).getValue()="0"
}

predicate func_77(Variable vl_tcp_3880, EqualityOperation target_77) {
		target_77.getAnOperand().(PointerFieldAccess).getTarget().getName()="ppt_buffer"
		and target_77.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_77.getAnOperand() instanceof OctalLiteral
}

predicate func_78(Variable vl_tcp_3880, BlockStmt target_78) {
		target_78.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_78.getStmt(1).(ExprStmt).getExpr() instanceof AssignExpr
		and target_78.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_78.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_78.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_83(Parameter vp_manager_3876, ExprStmt target_83) {
		target_83.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_83.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3876
		and target_83.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_83.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to read PPT marker\n"
}

predicate func_87(Variable vl_tcp_3880, ExprStmt target_87) {
		target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_87.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_92(Parameter vp_header_size_3875, Variable vl_tcp_3880, BlockStmt target_92) {
		target_92.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_data_size"
		and target_92.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_92.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_92.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt_len"
		and target_92.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_3880
		and target_92.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_header_size_3875
}

from Function func, Parameter vp_header_data_3874, Parameter vp_header_size_3875, Parameter vp_manager_3876, Variable vl_tcp_3880, Variable vl_Z_ppt_3881, Variable vnew_ppt_buffer_3924, Literal target_0, PointerFieldAccess target_1, VariableAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, SizeofTypeOperator target_8, VariableAccess target_9, ExprStmt target_31, ReturnStmt target_32, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, VariableAccess target_36, VariableAccess target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, VariableAccess target_41, VariableAccess target_42, VariableAccess target_43, VariableAccess target_44, VariableAccess target_45, VariableAccess target_46, VariableAccess target_50, FunctionCall target_51, PointerFieldAccess target_52, PointerFieldAccess target_53, AssignExpr target_55, AssignAddExpr target_57, AssignExpr target_58, NotExpr target_60, FunctionCall target_61, AssignExpr target_62, PointerFieldAccess target_63, AssignExpr target_64, AssignExpr target_65, ExprStmt target_66, PointerArithmeticOperation target_67, ExprStmt target_68, PointerArithmeticOperation target_69, ExprStmt target_70, ExprStmt target_71, ExprStmt target_72, EqualityOperation target_75, EqualityOperation target_77, BlockStmt target_78, ExprStmt target_83, ExprStmt target_87, BlockStmt target_92
where
func_0(vp_header_size_3875, target_0)
and func_1(vl_tcp_3880, target_1)
and func_3(vp_header_size_3875, vl_tcp_3880, target_3)
and func_4(vl_tcp_3880, target_4)
and func_5(vl_tcp_3880, target_5)
and func_6(vl_tcp_3880, target_6)
and func_7(vl_tcp_3880, target_7)
and func_8(func, target_8)
and func_9(vp_header_size_3875, vl_tcp_3880, target_9)
and not func_10(vl_tcp_3880, target_71, target_72)
and not func_12(vl_tcp_3880)
and not func_13(vl_tcp_3880, target_72)
and not func_14(vl_tcp_3880, vl_Z_ppt_3881, target_75, target_72)
and not func_23(vp_manager_3876, vl_tcp_3880, vl_Z_ppt_3881, target_83, func)
and not func_25(vl_tcp_3880, vl_Z_ppt_3881, target_87, target_75)
and not func_26(vp_header_size_3875, target_66, target_70)
and not func_27(vp_manager_3876, vl_tcp_3880, vl_Z_ppt_3881, target_31, func)
and not func_29(vl_tcp_3880, vl_Z_ppt_3881, target_87)
and not func_30(vl_tcp_3880, vl_Z_ppt_3881)
and func_31(vp_manager_3876, target_60, target_31)
and func_32(target_60, func, target_32)
and func_33(vl_Z_ppt_3881, target_92, target_33)
and func_34(vl_tcp_3880, target_34)
and func_35(vl_tcp_3880, target_35)
and func_36(vl_tcp_3880, target_36)
and func_37(vl_tcp_3880, target_37)
and func_38(vl_tcp_3880, target_38)
and func_39(vp_header_size_3875, vl_tcp_3880, target_39)
and func_40(vl_tcp_3880, target_40)
and func_41(vl_tcp_3880, target_41)
and func_42(vl_tcp_3880, target_42)
and func_43(vl_tcp_3880, target_43)
and func_44(vl_tcp_3880, target_44)
and func_45(vl_tcp_3880, target_45)
and func_46(vp_header_size_3875, target_46)
and func_50(vp_header_data_3874, vp_header_size_3875, target_50)
and func_51(vl_tcp_3880, target_71, target_72, target_51)
and func_52(vl_tcp_3880, target_52)
and func_53(vl_tcp_3880, target_72, target_53)
and func_55(vl_tcp_3880, target_77, target_55)
and func_57(vp_header_size_3875, vl_tcp_3880, target_57)
and func_58(vl_tcp_3880, vnew_ppt_buffer_3924, target_58)
and func_60(vnew_ppt_buffer_3924, target_78, target_60)
and func_61(vl_tcp_3880, target_61)
and func_62(vl_tcp_3880, target_62)
and func_63(vl_tcp_3880, target_63)
and func_64(vl_tcp_3880, vnew_ppt_buffer_3924, target_64)
and func_65(vl_tcp_3880, target_67, target_65)
and func_66(vp_header_size_3875, vl_tcp_3880, target_75, target_66)
and func_67(vl_tcp_3880, target_67)
and func_68(vp_header_data_3874, vp_header_size_3875, vl_tcp_3880, target_68)
and func_69(vl_tcp_3880, target_69)
and func_70(vp_header_size_3875, vl_tcp_3880, target_70)
and func_71(vp_header_size_3875, vl_tcp_3880, target_71)
and func_72(vl_tcp_3880, target_72)
and func_75(vl_Z_ppt_3881, target_75)
and func_77(vl_tcp_3880, target_77)
and func_78(vl_tcp_3880, target_78)
and func_83(vp_manager_3876, target_83)
and func_87(vl_tcp_3880, target_87)
and func_92(vp_header_size_3875, vl_tcp_3880, target_92)
and vp_header_data_3874.getType().hasName("OPJ_BYTE *")
and vp_header_size_3875.getType().hasName("OPJ_UINT32")
and vp_manager_3876.getType().hasName("opj_event_mgr_t *")
and vl_tcp_3880.getType().hasName("opj_tcp_t *")
and vl_Z_ppt_3881.getType().hasName("OPJ_UINT32")
and vnew_ppt_buffer_3924.getType().hasName("OPJ_BYTE *")
and vp_header_data_3874.getParentScope+() = func
and vp_header_size_3875.getParentScope+() = func
and vp_manager_3876.getParentScope+() = func
and vl_tcp_3880.getParentScope+() = func
and vl_Z_ppt_3881.getParentScope+() = func
and vnew_ppt_buffer_3924.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
