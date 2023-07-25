/**
 * @name libyang-298b30ea4ebee137226acf9bb38678bd82704582-lyxml_parse_elem
 * @id cpp/libyang/298b30ea4ebee137226acf9bb38678bd82704582/lyxml-parse-elem
 * @description libyang-298b30ea4ebee137226acf9bb38678bd82704582-src/xml.c-lyxml_parse_elem CVE-2021-28903
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_16, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getLesserOperand().(Literal).getValue()="10000"
		and target_0.getParent().(IfStmt).getThen()=target_16
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vctx_946, ExprStmt target_17) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ly_vlog")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_1.getArgument(3).(Literal).getValue()="0"
		and target_1.getArgument(4).(StringLiteral).getValue()="Recursion limit %d reached"
		and target_1.getArgument(5).(Literal).getValue()="10000"
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_18, Function func) {
	exists(EmptyStmt target_2 |
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_18, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vc_948, Variable velem_954, Variable vattr_955, Variable vsize_956, Variable vclosed_flag_957, Parameter vctx_946, NotExpr target_8, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, LogicalAndExpr target_22, AddressOfExpr target_23, ExprStmt target_24, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof NotExpr
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vc_948
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lydict_insert")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()=""
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclosed_flag_957
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_4.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_948
		and target_4.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="62"
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_948
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattr_955
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_attr")
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vattr_955
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="error"
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vc_948
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsize_956
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_955
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(GotoStmt).toString() = "goto ..."
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(GotoStmt).getName() ="process"
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_4)
		and target_8.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getOperand().(VariableAccess).getLocation().isBefore(target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_5(Parameter voptions_946, Variable vc_948, Variable velem_954, Variable vchild_954, Variable vsize_956, Parameter vctx_946, EqualityOperation target_25, BitwiseAndExpr target_26, BitwiseAndExpr target_27, ExprStmt target_14, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, NotExpr target_31, ExprStmt target_32, ExprStmt target_33) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_954
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lyxml_parse_elem")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_956
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=voptions_946
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_26.getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_27.getLeftOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_28.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_30.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getOperand().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_7(Parameter voptions_946, Variable vc_948, Variable velem_954, Variable vsize_956, Parameter vctx_946) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_7.getAnOperand().(Literal).getValue()="1"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lyxml_parse_elem")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_956
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=voptions_946)
}

*/
predicate func_8(Variable vc_948, BlockStmt target_16, NotExpr target_8) {
		target_8.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_8.getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="/>"
		and target_8.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_8.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_8.getParent().(IfStmt).getThen()=target_16
}

predicate func_9(Variable vc_948, EqualityOperation target_18, ExprStmt target_9) {
		target_9.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vc_948
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_10(Variable vlws_949, EqualityOperation target_18, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlws_949
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_11(Variable vlws_949, Variable velem_954, EqualityOperation target_25, IfStmt target_11) {
		target_11.getCondition().(VariableAccess).getTarget()=vlws_949
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="store_content"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlws_949
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_12(Variable v__func__, Parameter voptions_946, Variable velem_954, Variable vchild_954, Parameter vctx_946, EqualityOperation target_25, IfStmt target_12) {
		target_12.getCondition().(PointerFieldAccess).getTarget().getName()="content"
		and target_12.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=voptions_946
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="XML element with mixed content"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="error"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_954
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="72"
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vchild_954
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Memory allocation failed (%s())."
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=v__func__
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="error"
		and target_12.getThen().(BlockStmt).getStmt(3).(EmptyStmt).toString() = ";"
		and target_12.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_12.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_954
		and target_12.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_12.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_12.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lyxml_add_child")
		and target_12.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_12.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vchild_954
		and target_12.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_12.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_12.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_13(Variable vchild_954, EqualityOperation target_25, IfStmt target_13) {
		target_13.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vchild_954
		and target_13.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_13.getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="error"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_14(Variable vc_948, Variable vsize_956, EqualityOperation target_25, ExprStmt target_14) {
		target_14.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vc_948
		and target_14.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsize_956
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_15(Parameter voptions_946, Variable vc_948, Variable velem_954, Variable vsize_956, Parameter vctx_946, VariableAccess target_15) {
		target_15.getTarget()=vctx_946
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lyxml_parse_elem")
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_956
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=voptions_946
}

predicate func_16(Variable vc_948, Variable velem_954, Parameter vctx_946, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vc_948
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lydict_insert")
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()=""
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_17(Variable vc_948, Variable vsize_956, Parameter vctx_946, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_text")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(CharLiteral).getValue()="60"
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_956
}

predicate func_18(Variable vc_948, EqualityOperation target_18) {
		target_18.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_948
		and target_18.getAnOperand().(CharLiteral).getValue()="62"
}

predicate func_19(Variable vc_948, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vc_948
}

predicate func_20(Variable vc_948, Variable velem_954, Parameter vctx_946, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lydict_insert")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vc_948
}

predicate func_21(Variable velem_954, Variable vattr_955, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ns"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_21.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vattr_955
}

predicate func_22(Variable vattr_955, LogicalAndExpr target_22) {
		target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_22.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_955
}

predicate func_23(Variable vsize_956, AddressOfExpr target_23) {
		target_23.getOperand().(VariableAccess).getTarget()=vsize_956
}

predicate func_24(Variable velem_954, Parameter vctx_946, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_24.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_24.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="closing element tag"
		and target_24.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_24.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
}

predicate func_25(Variable vc_948, EqualityOperation target_25) {
		target_25.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_948
		and target_25.getAnOperand().(CharLiteral).getValue()="60"
}

predicate func_26(Parameter voptions_946, BitwiseAndExpr target_26) {
		target_26.getLeftOperand().(VariableAccess).getTarget()=voptions_946
		and target_26.getRightOperand().(Literal).getValue()="2"
}

predicate func_27(Parameter voptions_946, BitwiseAndExpr target_27) {
		target_27.getLeftOperand().(VariableAccess).getTarget()=voptions_946
		and target_27.getRightOperand().(Literal).getValue()="2"
}

predicate func_28(Variable velem_954, ExprStmt target_28) {
		target_28.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_28.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_28.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1"
}

predicate func_29(Variable velem_954, Parameter vctx_946, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_954
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lydict_insert_zc")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
}

predicate func_30(Variable velem_954, Variable vchild_954, Parameter vctx_946, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("lyxml_add_child")
		and target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_30.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=velem_954
		and target_30.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vchild_954
}

predicate func_31(Variable vchild_954, NotExpr target_31) {
		target_31.getOperand().(VariableAccess).getTarget()=vchild_954
}

predicate func_32(Variable vc_948, Variable vsize_956, ExprStmt target_32) {
		target_32.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vc_948
		and target_32.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsize_956
}

predicate func_33(Parameter voptions_946, Variable vc_948, Variable velem_954, Variable vchild_954, Variable vsize_956, Parameter vctx_946, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_954
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lyxml_parse_elem")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_946
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_948
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_956
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=velem_954
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=voptions_946
}

from Function func, Variable v__func__, Parameter voptions_946, Variable vc_948, Variable vlws_949, Variable velem_954, Variable vchild_954, Variable vattr_955, Variable vsize_956, Variable vclosed_flag_957, Parameter vctx_946, NotExpr target_8, ExprStmt target_9, ExprStmt target_10, IfStmt target_11, IfStmt target_12, IfStmt target_13, ExprStmt target_14, VariableAccess target_15, BlockStmt target_16, ExprStmt target_17, EqualityOperation target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, LogicalAndExpr target_22, AddressOfExpr target_23, ExprStmt target_24, EqualityOperation target_25, BitwiseAndExpr target_26, BitwiseAndExpr target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, NotExpr target_31, ExprStmt target_32, ExprStmt target_33
where
not func_0(target_16, func)
and not func_1(vctx_946, target_17)
and not func_2(target_18, func)
and not func_3(target_18, func)
and not func_4(vc_948, velem_954, vattr_955, vsize_956, vclosed_flag_957, vctx_946, target_8, target_19, target_20, target_21, target_22, target_23, target_24, func)
and func_8(vc_948, target_16, target_8)
and func_9(vc_948, target_18, target_9)
and func_10(vlws_949, target_18, target_10)
and func_11(vlws_949, velem_954, target_25, target_11)
and func_12(v__func__, voptions_946, velem_954, vchild_954, vctx_946, target_25, target_12)
and func_13(vchild_954, target_25, target_13)
and func_14(vc_948, vsize_956, target_25, target_14)
and func_15(voptions_946, vc_948, velem_954, vsize_956, vctx_946, target_15)
and func_16(vc_948, velem_954, vctx_946, target_16)
and func_17(vc_948, vsize_956, vctx_946, target_17)
and func_18(vc_948, target_18)
and func_19(vc_948, target_19)
and func_20(vc_948, velem_954, vctx_946, target_20)
and func_21(velem_954, vattr_955, target_21)
and func_22(vattr_955, target_22)
and func_23(vsize_956, target_23)
and func_24(velem_954, vctx_946, target_24)
and func_25(vc_948, target_25)
and func_26(voptions_946, target_26)
and func_27(voptions_946, target_27)
and func_28(velem_954, target_28)
and func_29(velem_954, vctx_946, target_29)
and func_30(velem_954, vchild_954, vctx_946, target_30)
and func_31(vchild_954, target_31)
and func_32(vc_948, vsize_956, target_32)
and func_33(voptions_946, vc_948, velem_954, vchild_954, vsize_956, vctx_946, target_33)
and v__func__.getType() instanceof ArrayType
and voptions_946.getType().hasName("int")
and vc_948.getType().hasName("const char *")
and vlws_949.getType().hasName("const char *")
and velem_954.getType().hasName("lyxml_elem *")
and vchild_954.getType().hasName("lyxml_elem *")
and vattr_955.getType().hasName("lyxml_attr *")
and vsize_956.getType().hasName("unsigned int")
and vclosed_flag_957.getType().hasName("int")
and vctx_946.getType().hasName("ly_ctx *")
and not v__func__.getParentScope+() = func
and voptions_946.getParentScope+() = func
and vc_948.getParentScope+() = func
and vlws_949.getParentScope+() = func
and velem_954.getParentScope+() = func
and vchild_954.getParentScope+() = func
and vattr_955.getParentScope+() = func
and vsize_956.getParentScope+() = func
and vclosed_flag_957.getParentScope+() = func
and vctx_946.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
