/**
 * @name httpd-d4901cb32133bc0e59ad193a29d1665597080d67-fix_uds_filename
 * @id cpp/httpd/d4901cb32133bc0e59ad193a29d1665597080d67/fix-uds-filename
 * @description httpd-d4901cb32133bc0e59ad193a29d1665597080d67-fix_uds_filename CVE-2021-40438
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptr_2280, VariableAccess target_0) {
		target_0.getTarget()=vptr_2280
}

predicate func_1(Parameter vr_2278, Variable vptr2_2280, Variable vurisock_2286, VariableAccess target_1) {
		target_1.getTarget()=vptr2_2280
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apr_uri_parse")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vurisock_2286
}

/*predicate func_2(Variable vptr_2280, VariableAccess target_2) {
		target_2.getTarget()=vptr_2280
}

*/
/*predicate func_3(Variable vptr_2280, ExprStmt target_49, ExprStmt target_50, Literal target_3) {
		target_3.getValue()="1"
		and not target_3.getValue()="5"
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_2280
		and target_49.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_50.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_4(Parameter vr_2278, Variable vsockpath_2292, VariableAccess target_4) {
		target_4.getTarget()=vsockpath_2292
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("apr_table_setn")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="notes"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="uds_path"
}

/*predicate func_5(Variable vrurl_2291, VariableAccess target_5) {
		target_5.getTarget()=vrurl_2291
		and target_5.getParent().(FunctionCall).getParent().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
}

*/
predicate func_6(Parameter vr_2278, Parameter vurl_2278, Variable vsockpath_2292, VariableAccess target_6) {
		target_6.getTarget()=vsockpath_2292
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof ConditionalExpr
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddExpr).getValue()="9"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_2278
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="*: rewrite of url due to UDS(%s): %s (%s)"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="filename"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
}

predicate func_7(Variable vptr2_2280, VariableAccess target_7) {
		target_7.getTarget()=vptr2_2280
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
}

predicate func_8(Function func, Literal target_8) {
		target_8.getValue()="6"
		and not target_8.getValue()="0"
		and target_8.getParent().(PointerAddExpr).getParent().(PointerAddExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vptr_2280, Variable vptr2_2280, VariableAccess target_9) {
		target_9.getTarget()=vptr_2280
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr2_2280
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="124"
}

/*predicate func_10(Variable vptr2_2280, VariableAccess target_10) {
		target_10.getTarget()=vptr2_2280
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="124"
}

*/
predicate func_11(Variable vptr_2280, Initializer target_11) {
		target_11.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_2280
		and target_11.getExpr().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_12(Function func, Initializer target_12) {
		target_12.getExpr() instanceof FunctionCall
		and target_12.getExpr().getEnclosingFunction() = func
}

predicate func_13(Parameter vr_2278, Variable vrurl_2291, FunctionCall target_13) {
		target_13.getTarget().hasName("apr_pstrdup")
		and not target_13.getTarget().hasName("apr_pstrmemdup")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_13.getArgument(1).(VariableAccess).getTarget()=vrurl_2291
}

predicate func_14(Parameter vr_2278, Variable vrurl_2291, FunctionCall target_14) {
		target_14.getTarget().hasName("memmove")
		and not target_14.getTarget().hasName("memcpy")
		and target_14.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_14.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_14.getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="6"
		and target_14.getArgument(1).(VariableAccess).getTarget()=vrurl_2291
		and target_14.getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_14.getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrurl_2291
		and target_14.getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

/*predicate func_15(Parameter vr_2278, ConditionalExpr target_52, Literal target_15) {
		target_15.getValue()="6"
		and not target_15.getValue()="0"
		and target_15.getParent().(PointerAddExpr).getParent().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_15.getParent().(PointerAddExpr).getParent().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_15.getParent().(PointerAddExpr).getParent().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_52.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_16(Variable vptr_2280, VariableAccess target_16) {
		target_16.getTarget()=vptr_2280
}

predicate func_18(Function func) {
	exists(PostfixIncrExpr target_18 |
		target_18.getOperand().(VariableAccess).getType().hasName("char *")
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Variable vurisock_2286, BlockStmt target_53, AddressOfExpr target_54, ValueFieldAccess target_55) {
	exists(LogicalAndExpr target_19 |
		target_19.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_19.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="path"
		and target_19.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vurisock_2286
		and target_19.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="hostname"
		and target_19.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("apr_uri_t")
		and target_19.getParent().(IfStmt).getThen()=target_53
		and target_54.getOperand().(VariableAccess).getLocation().isBefore(target_19.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_55.getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_20(Function func) {
	exists(ValueFieldAccess target_20 |
		target_20.getTarget().getName()="hostname"
		and target_20.getQualifier().(VariableAccess).getType().hasName("apr_uri_t")
		and target_20.getEnclosingFunction() = func)
}

*/
predicate func_22(Parameter vr_2278, EqualityOperation target_39, ExprStmt target_56) {
	exists(DoStmt target_22 |
		target_22.getCondition().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getValue()="1"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="level"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseAndExpr).getValue()="3"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof ConditionalExpr
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="3"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_2278
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="AH10292: Invalid proxy UDS filename (%s)"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_56.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

/*predicate func_23(Parameter vr_2278, ReturnStmt target_57) {
	exists(RelationalOperation target_23 |
		 (target_23 instanceof GEExpr or target_23 instanceof LEExpr)
		and target_23.getValue()="1"
		and target_23.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vr_2278
		and target_23.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_23.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_23.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_57)
}

*/
/*predicate func_24(Parameter vr_2278, ReturnStmt target_57) {
	exists(RelationalOperation target_24 |
		 (target_24 instanceof GEExpr or target_24 instanceof LEExpr)
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("int *")
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="module_levels"
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="module_levels"
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("int *")
		and target_24.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="level"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="connection"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="connection"
		and target_24.getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="module_levels"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("int *")
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("int *")
		and target_24.getGreaterOperand().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-1"
		and target_24.getLesserOperand().(BitwiseAndExpr).getValue()="3"
		and target_24.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vr_2278
		and target_24.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_24.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_24.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_57)
}

*/
predicate func_26(Function func) {
	exists(AssignExpr target_26 |
		target_26.getLValue().(VariableAccess).getType().hasName("apr_size_t")
		and target_26.getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_26.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Parameter vr_2278, LogicalAndExpr target_58, ExprStmt target_59, PointerArithmeticOperation target_60) {
	exists(ExprStmt target_27 |
		target_27.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apr_pstrmemdup")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char *")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("apr_size_t")
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_58
		and target_59.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_60.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_29(Parameter vurl_2278, LogicalAndExpr target_58, PointerDereferenceExpr target_62) {
	exists(ExprStmt target_29 |
		target_29.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_29.getExpr().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_29.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getType().hasName("apr_size_t")
		and target_29.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_58
		and target_29.getExpr().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_62.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_30(Parameter vurl_2278, PointerDereferenceExpr target_62) {
	exists(PointerDereferenceExpr target_30 |
		target_30.getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_30.getOperand().(VariableAccess).getLocation().isBefore(target_62.getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_34(Parameter vurl_2278, PointerDereferenceExpr target_34) {
		target_34.getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_34.getParent().(AssignExpr).getLValue() = target_34
		and target_34.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

/*predicate func_35(Parameter vr_2278, Parameter vurl_2278, Variable vaplog_module_index, Variable vsockpath_2292, ConditionalExpr target_35) {
		target_35.getCondition().(VariableAccess).getTarget()=vaplog_module_index
		and target_35.getThen().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vaplog_module_index
		and target_35.getElse().(UnaryMinusExpr).getValue()="-1"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddExpr).getValue()="9"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_2278
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="*: rewrite of url due to UDS(%s): %s (%s)"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsockpath_2292
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="filename"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
}

*/
/*predicate func_36(Parameter vr_2278, Parameter vurl_2278, Variable vaplog_module_index, Variable vsockpath_2292, PointerFieldAccess target_36) {
		target_36.getTarget().getName()="filename"
		and target_36.getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vaplog_module_index
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vaplog_module_index
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-1"
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddExpr).getValue()="9"
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_2278
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="*: rewrite of url due to UDS(%s): %s (%s)"
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsockpath_2292
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vurl_2278
}

*/
predicate func_37(Parameter vr_2278, PointerFieldAccess target_37) {
		target_37.getTarget().getName()="filename"
		and target_37.getQualifier().(VariableAccess).getTarget()=vr_2278
}

predicate func_38(Parameter vr_2278, PointerArithmeticOperation target_38) {
		target_38.getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_38.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_38.getAnOperand().(Literal).getValue()="6"
		and target_38.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmpn")
		and target_38.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="unix:"
		and target_38.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
}

predicate func_39(Variable vrv_2287, BlockStmt target_53, EqualityOperation target_39) {
		target_39.getAnOperand().(VariableAccess).getTarget()=vrv_2287
		and target_39.getAnOperand().(Literal).getValue()="0"
		and target_39.getParent().(IfStmt).getThen()=target_53
}

predicate func_40(Parameter vr_2278, Variable vurisock_2286, FunctionCall target_40) {
		target_40.getTarget().hasName("ap_runtime_dir_relative")
		and target_40.getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_40.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_40.getArgument(1).(ValueFieldAccess).getTarget().getName()="path"
		and target_40.getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vurisock_2286
}

predicate func_41(Parameter vr_2278, VariableAccess target_41) {
		target_41.getTarget()=vr_2278
}

predicate func_42(Parameter vr_2278, VariableAccess target_42) {
		target_42.getTarget()=vr_2278
}

predicate func_43(Parameter vr_2278, VariableAccess target_43) {
		target_43.getTarget()=vr_2278
}

predicate func_45(Parameter vr_2278, Variable vptr_2280, Variable vptr2_2280, BlockStmt target_64, CommaExpr target_45) {
		target_45.getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr2_2280
		and target_45.getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_45.getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_45.getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_45.getLeftOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_45.getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_2280
		and target_45.getRightOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_45.getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr2_2280
		and target_45.getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="124"
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="proxy:"
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmpn")
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="unix:"
		and target_45.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_45.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_64
}

/*predicate func_46(Parameter vr_2278, Variable vptr2_2280, PointerArithmeticOperation target_46) {
		target_46.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_46.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_46.getAnOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_46.getAnOperand() instanceof Literal
		and target_46.getParent().(AssignExpr).getRValue() = target_46
		and target_46.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr2_2280
}

*/
predicate func_48(Parameter vr_2278, ConditionalExpr target_52, PointerFieldAccess target_48) {
		target_48.getTarget().getName()="filename"
		and target_48.getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_48.getQualifier().(VariableAccess).getLocation().isBefore(target_52.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_49(Variable vptr_2280, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_2280
		and target_49.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_50(Variable vptr_2280, ExprStmt target_50) {
		target_50.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_2280
		and target_50.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="124"
}

predicate func_52(Parameter vr_2278, ConditionalExpr target_52) {
		target_52.getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_52.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_52.getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_52.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_52.getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="log"
		and target_52.getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="connection"
		and target_52.getElse().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_52.getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="log"
		and target_52.getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="connection"
		and target_52.getElse().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_52.getElse().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="log"
		and target_52.getElse().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="server"
		and target_52.getElse().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
}

predicate func_53(Parameter vr_2278, Variable vsockpath_2292, BlockStmt target_53) {
		target_53.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("apr_table_setn")
		and target_53.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="notes"
		and target_53.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_53.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="uds_path"
		and target_53.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsockpath_2292
}

predicate func_54(Variable vurisock_2286, AddressOfExpr target_54) {
		target_54.getOperand().(VariableAccess).getTarget()=vurisock_2286
}

predicate func_55(Variable vurisock_2286, ValueFieldAccess target_55) {
		target_55.getTarget().getName()="path"
		and target_55.getQualifier().(VariableAccess).getTarget()=vurisock_2286
}

predicate func_56(Parameter vr_2278, Parameter vurl_2278, Variable vsockpath_2292, ExprStmt target_56) {
		target_56.getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_56.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_56.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_56.getExpr().(FunctionCall).getArgument(2) instanceof ConditionalExpr
		and target_56.getExpr().(FunctionCall).getArgument(3).(AddExpr).getValue()="9"
		and target_56.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_56.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_2278
		and target_56.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="*: rewrite of url due to UDS(%s): %s (%s)"
		and target_56.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsockpath_2292
		and target_56.getExpr().(FunctionCall).getArgument(8).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vurl_2278
		and target_56.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="filename"
		and target_56.getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
}

predicate func_58(Parameter vr_2278, LogicalAndExpr target_58) {
		target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="proxy:"
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmpn")
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="unix:"
		and target_58.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_58.getAnOperand() instanceof CommaExpr
}

predicate func_59(Parameter vr_2278, Variable vsockpath_2292, ExprStmt target_59) {
		target_59.getExpr().(FunctionCall).getTarget().hasName("apr_table_setn")
		and target_59.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="notes"
		and target_59.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_59.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="uds_path"
		and target_59.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsockpath_2292
}

predicate func_60(Parameter vr_2278, PointerArithmeticOperation target_60) {
		target_60.getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_60.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_60.getAnOperand() instanceof Literal
}

predicate func_62(Parameter vurl_2278, PointerDereferenceExpr target_62) {
		target_62.getOperand().(VariableAccess).getTarget()=vurl_2278
}

predicate func_64(Parameter vr_2278, Variable vptr_2280, Variable vptr2_2280, Variable vurisock_2286, Variable vrv_2287, BlockStmt target_64) {
		target_64.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_2280
		and target_64.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrv_2287
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apr_uri_parse")
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_2278
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr2_2280
		and target_64.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vurisock_2286
}

from Function func, Parameter vr_2278, Parameter vurl_2278, Variable vptr_2280, Variable vptr2_2280, Variable vaplog_module_index, Variable vurisock_2286, Variable vrv_2287, Variable vrurl_2291, Variable vsockpath_2292, VariableAccess target_0, VariableAccess target_1, VariableAccess target_4, VariableAccess target_6, VariableAccess target_7, Literal target_8, VariableAccess target_9, Initializer target_11, Initializer target_12, FunctionCall target_13, FunctionCall target_14, VariableAccess target_16, PointerDereferenceExpr target_34, PointerFieldAccess target_37, PointerArithmeticOperation target_38, EqualityOperation target_39, FunctionCall target_40, VariableAccess target_41, VariableAccess target_42, VariableAccess target_43, CommaExpr target_45, PointerFieldAccess target_48, ExprStmt target_49, ExprStmt target_50, ConditionalExpr target_52, BlockStmt target_53, AddressOfExpr target_54, ValueFieldAccess target_55, ExprStmt target_56, LogicalAndExpr target_58, ExprStmt target_59, PointerArithmeticOperation target_60, PointerDereferenceExpr target_62, BlockStmt target_64
where
func_0(vptr_2280, target_0)
and func_1(vr_2278, vptr2_2280, vurisock_2286, target_1)
and func_4(vr_2278, vsockpath_2292, target_4)
and func_6(vr_2278, vurl_2278, vsockpath_2292, target_6)
and func_7(vptr2_2280, target_7)
and func_8(func, target_8)
and func_9(vptr_2280, vptr2_2280, target_9)
and func_11(vptr_2280, target_11)
and func_12(func, target_12)
and func_13(vr_2278, vrurl_2291, target_13)
and func_14(vr_2278, vrurl_2291, target_14)
and func_16(vptr_2280, target_16)
and not func_18(func)
and not func_19(vurisock_2286, target_53, target_54, target_55)
and not func_22(vr_2278, target_39, target_56)
and not func_26(func)
and not func_27(vr_2278, target_58, target_59, target_60)
and not func_29(vurl_2278, target_58, target_62)
and func_34(vurl_2278, target_34)
and func_37(vr_2278, target_37)
and func_38(vr_2278, target_38)
and func_39(vrv_2287, target_53, target_39)
and func_40(vr_2278, vurisock_2286, target_40)
and func_41(vr_2278, target_41)
and func_42(vr_2278, target_42)
and func_43(vr_2278, target_43)
and func_45(vr_2278, vptr_2280, vptr2_2280, target_64, target_45)
and func_48(vr_2278, target_52, target_48)
and func_49(vptr_2280, target_49)
and func_50(vptr_2280, target_50)
and func_52(vr_2278, target_52)
and func_53(vr_2278, vsockpath_2292, target_53)
and func_54(vurisock_2286, target_54)
and func_55(vurisock_2286, target_55)
and func_56(vr_2278, vurl_2278, vsockpath_2292, target_56)
and func_58(vr_2278, target_58)
and func_59(vr_2278, vsockpath_2292, target_59)
and func_60(vr_2278, target_60)
and func_62(vurl_2278, target_62)
and func_64(vr_2278, vptr_2280, vptr2_2280, vurisock_2286, vrv_2287, target_64)
and vr_2278.getType().hasName("request_rec *")
and vurl_2278.getType().hasName("char **")
and vptr_2280.getType().hasName("char *")
and vptr2_2280.getType().hasName("char *")
and vaplog_module_index.getType().hasName("int *")
and vurisock_2286.getType().hasName("apr_uri_t")
and vrv_2287.getType().hasName("apr_status_t")
and vrurl_2291.getType().hasName("char *")
and vsockpath_2292.getType().hasName("char *")
and vr_2278.getParentScope+() = func
and vurl_2278.getParentScope+() = func
and vptr_2280.getParentScope+() = func
and vptr2_2280.getParentScope+() = func
and not vaplog_module_index.getParentScope+() = func
and vurisock_2286.getParentScope+() = func
and vrv_2287.getParentScope+() = func
and vrurl_2291.getParentScope+() = func
and vsockpath_2292.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
