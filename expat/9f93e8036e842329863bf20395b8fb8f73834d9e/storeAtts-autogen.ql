/**
 * @name expat-9f93e8036e842329863bf20395b8fb8f73834d9e-storeAtts
 * @id cpp/expat/9f93e8036e842329863bf20395b8fb8f73834d9e/storeAtts
 * @description expat-9f93e8036e842329863bf20395b8fb8f73834d9e-expat/lib/xmlparse.c-storeAtts CVE-2022-22822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnDefaultAtts_3235, Variable vn_3240, BlockStmt target_22, ExprStmt target_23, RelationalOperation target_5, ExprStmt target_24) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vn_3240
		and target_0.getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_0.getParent().(IfStmt).getThen()=target_22
		and target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_5, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnDefaultAtts_3235, Variable vn_3240, RelationalOperation target_13, RelationalOperation target_25, MulExpr target_26, ExprStmt target_17) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="2147483631"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_3240
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_25.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_26.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vprefixLen_3238, Variable vi_3239, Variable vbinding_3243, ExprStmt target_27, IfStmt target_28, MulExpr target_29, RelationalOperation target_13, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="uriLen"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vprefixLen_3238
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_3239
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="uriLen"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vprefixLen_3238
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_3)
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_28.getCondition().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_29.getLeftOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vn_3240, ExprStmt target_17, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_3240
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="2147483623"
		and target_4.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_4.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(6) instanceof ForStmt
		and target_4.getThen().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(39)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(39).getFollowingStmt()=target_4)
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vparser_3230, Variable vnDefaultAtts_3235, Variable vn_3240, BlockStmt target_22, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_3240
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_5.getLesserOperand().(PointerFieldAccess).getTarget().getName()="m_attsSize"
		and target_5.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_5.getParent().(IfStmt).getThen()=target_22
}

predicate func_6(RelationalOperation target_5, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getEnclosingFunction() = func
}

predicate func_7(RelationalOperation target_5, Function func, DeclStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Parameter vparser_3230, Variable vnDefaultAtts_3235, Variable vn_3240, RelationalOperation target_5, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_attsSize"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_3240
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_9(Parameter vparser_3230, Variable vtemp_3266, RelationalOperation target_5, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtemp_3266
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="realloc_fcn"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="m_atts"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="m_attsSize"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="32"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_10(Parameter vparser_3230, Variable voldAttsSize_3265, Variable vtemp_3266, RelationalOperation target_5, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtemp_3266
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_attsSize"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voldAttsSize_3265
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_11(Parameter vparser_3230, Variable vtemp_3266, RelationalOperation target_5, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_atts"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtemp_3266
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_12(Parameter vparser_3230, Parameter venc_3230, Parameter vattStr_3230, Variable vn_3240, Variable voldAttsSize_3265, RelationalOperation target_5, IfStmt target_12) {
		target_12.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_3240
		and target_12.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voldAttsSize_3265
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="getAtts"
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_3230
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_3230
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vattStr_3230
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vn_3240
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m_atts"
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_13(Variable vn_3240, Variable vbinding_3243, BlockStmt target_30, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vn_3240
		and target_13.getLesserOperand().(PointerFieldAccess).getTarget().getName()="uriAlloc"
		and target_13.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_13.getParent().(IfStmt).getThen()=target_30
}

predicate func_14(RelationalOperation target_13, Function func, DeclStmt target_14) {
		target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Parameter vparser_3230, Variable vn_3240, Variable vuri_3241, RelationalOperation target_13, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuri_3241
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="malloc_fcn"
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_3240
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="24"
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_15.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_16(Variable vuri_3241, RelationalOperation target_13, IfStmt target_16) {
		target_16.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vuri_3241
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_17(Variable vn_3240, Variable vbinding_3243, RelationalOperation target_13, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="uriAlloc"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_3240
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="24"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_18(Variable vuri_3241, Variable vbinding_3243, RelationalOperation target_13, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuri_3241
		and target_18.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="uri"
		and target_18.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_18.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="uriLen"
		and target_18.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_18.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_18.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_19(Parameter vparser_3230, Variable vuri_3241, Variable vbinding_3243, Variable vp_3615, RelationalOperation target_13, ForStmt target_19) {
		target_19.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_3615
		and target_19.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="m_tagStack"
		and target_19.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_19.getCondition().(VariableAccess).getTarget()=vp_3615
		and target_19.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_3615
		and target_19.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_19.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3615
		and target_19.getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="str"
		and target_19.getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="name"
		and target_19.getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3615
		and target_19.getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="uri"
		and target_19.getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_19.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_19.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="name"
		and target_19.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3615
		and target_19.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vuri_3241
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_20(Parameter vparser_3230, Variable vbinding_3243, RelationalOperation target_13, ExprStmt target_20) {
		target_20.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_fcn"
		and target_20.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_20.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_20.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="uri"
		and target_20.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_21(Variable vuri_3241, Variable vbinding_3243, RelationalOperation target_13, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="uri"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_21.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vuri_3241
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_22(BlockStmt target_22) {
		target_22.getStmt(2) instanceof ExprStmt
		and target_22.getStmt(3) instanceof ExprStmt
		and target_22.getStmt(4) instanceof IfStmt
		and target_22.getStmt(5) instanceof ExprStmt
		and target_22.getStmt(6) instanceof IfStmt
}

predicate func_23(Variable vnDefaultAtts_3235, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnDefaultAtts_3235
		and target_23.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="nDefaultAtts"
}

predicate func_24(Parameter vparser_3230, Parameter venc_3230, Parameter vattStr_3230, Variable vn_3240, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_3240
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="getAtts"
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_3230
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=venc_3230
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vattStr_3230
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m_attsSize"
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m_atts"
		and target_24.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
}

predicate func_25(Variable vnDefaultAtts_3235, Variable vi_3239, RelationalOperation target_25) {
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getLesserOperand().(VariableAccess).getTarget()=vi_3239
		and target_25.getGreaterOperand().(VariableAccess).getTarget()=vnDefaultAtts_3235
}

predicate func_26(Variable vn_3240, MulExpr target_26) {
		target_26.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_3240
		and target_26.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="24"
		and target_26.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_26.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_27(Variable vprefixLen_3238, Variable vi_3239, Variable vn_3240, Variable vbinding_3243, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_3240
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_3239
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="uriLen"
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbinding_3243
		and target_27.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vprefixLen_3238
}

predicate func_28(Parameter vparser_3230, Variable vprefixLen_3238, Variable vi_3239, Variable vuri_3241, IfStmt target_28) {
		target_28.getCondition().(VariableAccess).getTarget()=vprefixLen_3238
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vuri_3241
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_3239
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vuri_3241
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="m_namespaceSeparator"
		and target_28.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3230
}

predicate func_29(Variable vi_3239, MulExpr target_29) {
		target_29.getLeftOperand().(VariableAccess).getTarget()=vi_3239
		and target_29.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_29.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_30(BlockStmt target_30) {
		target_30.getStmt(1) instanceof ExprStmt
		and target_30.getStmt(2) instanceof IfStmt
		and target_30.getStmt(3) instanceof ExprStmt
		and target_30.getStmt(4) instanceof ExprStmt
		and target_30.getStmt(5) instanceof ForStmt
}

from Function func, Parameter vparser_3230, Parameter venc_3230, Parameter vattStr_3230, Variable vnDefaultAtts_3235, Variable vprefixLen_3238, Variable vi_3239, Variable vn_3240, Variable vuri_3241, Variable vbinding_3243, Variable voldAttsSize_3265, Variable vtemp_3266, Variable vp_3615, RelationalOperation target_5, DeclStmt target_6, DeclStmt target_7, ExprStmt target_8, ExprStmt target_9, IfStmt target_10, ExprStmt target_11, IfStmt target_12, RelationalOperation target_13, DeclStmt target_14, ExprStmt target_15, IfStmt target_16, ExprStmt target_17, ExprStmt target_18, ForStmt target_19, ExprStmt target_20, ExprStmt target_21, BlockStmt target_22, ExprStmt target_23, ExprStmt target_24, RelationalOperation target_25, MulExpr target_26, ExprStmt target_27, IfStmt target_28, MulExpr target_29, BlockStmt target_30
where
not func_0(vnDefaultAtts_3235, vn_3240, target_22, target_23, target_5, target_24)
and not func_1(target_5, func)
and not func_2(vnDefaultAtts_3235, vn_3240, target_13, target_25, target_26, target_17)
and not func_3(vprefixLen_3238, vi_3239, vbinding_3243, target_27, target_28, target_29, target_13, func)
and not func_4(vn_3240, target_17, func)
and func_5(vparser_3230, vnDefaultAtts_3235, vn_3240, target_22, target_5)
and func_6(target_5, func, target_6)
and func_7(target_5, func, target_7)
and func_8(vparser_3230, vnDefaultAtts_3235, vn_3240, target_5, target_8)
and func_9(vparser_3230, vtemp_3266, target_5, target_9)
and func_10(vparser_3230, voldAttsSize_3265, vtemp_3266, target_5, target_10)
and func_11(vparser_3230, vtemp_3266, target_5, target_11)
and func_12(vparser_3230, venc_3230, vattStr_3230, vn_3240, voldAttsSize_3265, target_5, target_12)
and func_13(vn_3240, vbinding_3243, target_30, target_13)
and func_14(target_13, func, target_14)
and func_15(vparser_3230, vn_3240, vuri_3241, target_13, target_15)
and func_16(vuri_3241, target_13, target_16)
and func_17(vn_3240, vbinding_3243, target_13, target_17)
and func_18(vuri_3241, vbinding_3243, target_13, target_18)
and func_19(vparser_3230, vuri_3241, vbinding_3243, vp_3615, target_13, target_19)
and func_20(vparser_3230, vbinding_3243, target_13, target_20)
and func_21(vuri_3241, vbinding_3243, target_13, target_21)
and func_22(target_22)
and func_23(vnDefaultAtts_3235, target_23)
and func_24(vparser_3230, venc_3230, vattStr_3230, vn_3240, target_24)
and func_25(vnDefaultAtts_3235, vi_3239, target_25)
and func_26(vn_3240, target_26)
and func_27(vprefixLen_3238, vi_3239, vn_3240, vbinding_3243, target_27)
and func_28(vparser_3230, vprefixLen_3238, vi_3239, vuri_3241, target_28)
and func_29(vi_3239, target_29)
and func_30(target_30)
and vparser_3230.getType().hasName("XML_Parser")
and venc_3230.getType().hasName("const ENCODING *")
and vattStr_3230.getType().hasName("const char *")
and vnDefaultAtts_3235.getType().hasName("int")
and vprefixLen_3238.getType().hasName("int")
and vi_3239.getType().hasName("int")
and vn_3240.getType().hasName("int")
and vuri_3241.getType().hasName("XML_Char *")
and vbinding_3243.getType().hasName("BINDING *")
and voldAttsSize_3265.getType().hasName("int")
and vtemp_3266.getType().hasName("ATTRIBUTE *")
and vp_3615.getType().hasName("TAG *")
and vparser_3230.getParentScope+() = func
and venc_3230.getParentScope+() = func
and vattStr_3230.getParentScope+() = func
and vnDefaultAtts_3235.getParentScope+() = func
and vprefixLen_3238.getParentScope+() = func
and vi_3239.getParentScope+() = func
and vn_3240.getParentScope+() = func
and vuri_3241.getParentScope+() = func
and vbinding_3243.getParentScope+() = func
and voldAttsSize_3265.getParentScope+() = func
and vtemp_3266.getParentScope+() = func
and vp_3615.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
