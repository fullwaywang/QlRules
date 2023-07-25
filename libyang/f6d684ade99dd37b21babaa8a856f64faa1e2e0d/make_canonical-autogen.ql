/**
 * @name libyang-f6d684ade99dd37b21babaa8a856f64faa1e2e0d-make_canonical
 * @id cpp/libyang/f6d684ade99dd37b21babaa8a856f64faa1e2e0d/make-canonical
 * @description libyang-f6d684ade99dd37b21babaa8a856f64faa1e2e0d-src/parser.c-make_canonical CVE-2019-19333
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_985, Literal target_0) {
		target_0.getValue()="1028"
		and not target_0.getValue()="1032"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
}

predicate func_1(Parameter vctx_985, Literal target_1) {
		target_1.getValue()="1038"
		and not target_1.getValue()="1086"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="1"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getEnclosingFunction() = func
}

/*predicate func_5(Function func, StringLiteral target_5) {
		target_5.getValue()="Internal error (%s:%d)."
		and not target_5.getValue()="Value \"%s\" is too long."
		and target_5.getEnclosingFunction() = func
}

*/
/*predicate func_6(Function func, StringLiteral target_6) {
		target_6.getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and not target_6.getValue()="Value \"%s\" is too long."
		and target_6.getEnclosingFunction() = func
}

*/
predicate func_7(Parameter vctx_985, ExprStmt target_70, ExprStmt target_71, Literal target_7) {
		target_7.getValue()="1054"
		and not target_7.getValue()="1"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_70.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_71.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_8(Function func, Literal target_8) {
		target_8.getValue()="0"
		and not target_8.getValue()="1"
		and target_8.getEnclosingFunction() = func
}

/*predicate func_10(Function func, StringLiteral target_10) {
		target_10.getValue()="Internal error (%s:%d)."
		and not target_10.getValue()="Value \"%s\" is too long."
		and target_10.getEnclosingFunction() = func
}

*/
/*predicate func_11(Function func, StringLiteral target_11) {
		target_11.getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and not target_11.getValue()="Value \"%s\" is too long."
		and target_11.getEnclosingFunction() = func
}

*/
predicate func_12(Parameter vctx_985, ExprStmt target_72, Literal target_12) {
		target_12.getValue()="1065"
		and not target_12.getValue()="1"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_72.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_13(Function func, Literal target_13) {
		target_13.getValue()="0"
		and not target_13.getValue()="1"
		and target_13.getEnclosingFunction() = func
}

/*predicate func_15(Function func, StringLiteral target_15) {
		target_15.getValue()="Internal error (%s:%d)."
		and not target_15.getValue()="Value \"%s\" is too long."
		and target_15.getEnclosingFunction() = func
}

*/
/*predicate func_16(Function func, StringLiteral target_16) {
		target_16.getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and not target_16.getValue()="Value \"%s\" is too long."
		and target_16.getEnclosingFunction() = func
}

*/
predicate func_17(Parameter vctx_985, ExprStmt target_73, Literal target_17) {
		target_17.getValue()="1073"
		and not target_17.getValue()="1"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_18(Function func, Literal target_18) {
		target_18.getValue()="0"
		and not target_18.getValue()="1"
		and target_18.getEnclosingFunction() = func
}

predicate func_20(Parameter vctx_985, ExprStmt target_74, Literal target_20) {
		target_20.getValue()="1082"
		and not target_20.getValue()="1"
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_74.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_21(Variable vbuf_len_987, Variable vbuf_988, Variable vbits_989, Variable vi_992, BlockStmt target_75, ExprStmt target_76, AddressOfExpr target_77, ArrayExpr target_78) {
	exists(RelationalOperation target_21 |
		 (target_21 instanceof GTExpr or target_21 instanceof LTExpr)
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_988
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbits_989
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_21.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_21.getParent().(IfStmt).getThen()=target_75
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_21.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_21.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_77.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_78.getArrayBase().(VariableAccess).getLocation().isBefore(target_21.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_22(Variable vbits_989, Variable vi_992, ArrayExpr target_79, RelationalOperation target_53) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="name"
		and target_22.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbits_989
		and target_22.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_79.getArrayOffset().(VariableAccess).getLocation().isBefore(target_22.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_22.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_23(Function func) {
	exists(UnaryMinusExpr target_23 |
		target_23.getValue()="-1"
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Variable vbuf_len_987, Variable vbits_989, Variable vi_992, BlockStmt target_80, RelationalOperation target_40, LogicalAndExpr target_39, LogicalAndExpr target_44) {
	exists(RelationalOperation target_24 |
		 (target_24 instanceof GTExpr or target_24 instanceof LTExpr)
		and target_24.getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_24.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_24.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbits_989
		and target_24.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_24.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_24.getParent().(IfStmt).getThen()=target_80
		and target_24.getLesserOperand().(VariableAccess).getLocation().isBefore(target_40.getLesserOperand().(VariableAccess).getLocation())
		and target_39.getAnOperand().(VariableAccess).getLocation().isBefore(target_24.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_24.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_44.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_25(Variable vbits_989, Variable vi_992, RelationalOperation target_53, SubExpr target_81) {
	exists(PointerFieldAccess target_25 |
		target_25.getTarget().getName()="name"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbits_989
		and target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_81.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_26(Function func) {
	exists(UnaryMinusExpr target_26 |
		target_26.getValue()="-1"
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Function func) {
	exists(UnaryMinusExpr target_27 |
		target_27.getValue()="-1"
		and target_27.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(UnaryMinusExpr target_29 |
		target_29.getValue()="-1"
		and target_29.getEnclosingFunction() = func)
}

predicate func_31(RelationalOperation target_57, Function func) {
	exists(EmptyStmt target_31 |
		target_31.toString() = ";"
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_31
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
		and target_31.getEnclosingFunction() = func)
}

predicate func_32(Function func) {
	exists(UnaryMinusExpr target_32 |
		target_32.getValue()="-1"
		and target_32.getEnclosingFunction() = func)
}

predicate func_33(Parameter vctx_985, Variable vend_991, RelationalOperation target_59, ExprStmt target_73, ExprStmt target_82) {
	exists(ExprStmt target_33 |
		target_33.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_33.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Value \"%s\" is too long."
		and target_33.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vend_991
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_33
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_82.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_34(RelationalOperation target_59, Function func) {
	exists(EmptyStmt target_34 |
		target_34.toString() = ";"
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_34
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
		and target_34.getEnclosingFunction() = func)
}

predicate func_35(Function func) {
	exists(UnaryMinusExpr target_35 |
		target_35.getValue()="-1"
		and target_35.getEnclosingFunction() = func)
}

predicate func_36(Parameter vctx_985, LogicalAndExpr target_44, ExprStmt target_71, ExprStmt target_74) {
	exists(IfStmt target_36 |
		target_36.getCondition() instanceof RelationalOperation
		and target_36.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Value \"%s\" is too long."
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="expr"
		and target_36.getThen().(BlockStmt).getStmt(2).(EmptyStmt).toString() = ";"
		and target_36.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_36
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
		and target_71.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_74.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_37(Parameter vctx_985, VariableAccess target_83, ExprStmt target_84, ExprStmt target_72) {
	exists(IfStmt target_37 |
		target_37.getCondition() instanceof RelationalOperation
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1086"
		and target_37.getThen().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_37.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_37.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_37.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_83
		and target_84.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_72.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_38(Variable vexp_990, BlockStmt target_75, NotExpr target_38) {
		target_38.getOperand().(VariableAccess).getTarget()=vexp_990
		and target_38.getParent().(IfStmt).getThen()=target_75
}

predicate func_39(Variable vexp_990, Variable vcur_expr_991, Variable vend_991, Variable vi_992, BlockStmt target_85, LogicalAndExpr target_39) {
		target_39.getAnOperand().(VariableAccess).getTarget()=vi_992
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_991
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="expr_pos"
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_992
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_39.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_expr_991
		and target_39.getParent().(IfStmt).getThen()=target_85
}

predicate func_40(Variable vbuf_len_987, Variable vcur_expr_991, Variable vend_991, Variable vcount_992, BlockStmt target_80, RelationalOperation target_40) {
		 (target_40 instanceof GTExpr or target_40 instanceof LTExpr)
		and target_40.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_992
		and target_40.getGreaterOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vcur_expr_991
		and target_40.getGreaterOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vend_991
		and target_40.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_40.getParent().(IfStmt).getThen()=target_80
}

predicate func_41(Variable vexp_990, RelationalOperation target_40, ExprStmt target_41) {
		target_41.getExpr().(FunctionCall).getTarget().hasName("lyxp_expr_free")
		and target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_990
		and target_41.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_40
}

predicate func_42(Variable vbuf_988, Variable vcur_expr_991, Variable vend_991, Variable vcount_992, LogicalAndExpr target_39, ExprStmt target_42) {
		target_42.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_42.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_988
		and target_42.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcount_992
		and target_42.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vend_991
		and target_42.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vcur_expr_991
		and target_42.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vend_991
		and target_42.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_43(Variable vcur_expr_991, Variable vend_991, Variable vcount_992, LogicalAndExpr target_39, ExprStmt target_43) {
		target_43.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcount_992
		and target_43.getExpr().(AssignAddExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vcur_expr_991
		and target_43.getExpr().(AssignAddExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vend_991
		and target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_44(Variable vexp_990, Variable vcur_expr_991, Variable vend_991, Variable vi_992, BlockStmt target_86, LogicalAndExpr target_44) {
		target_44.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tokens"
		and target_44.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_44.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_44.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_991
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strnchr")
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcur_expr_991
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="58"
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_44.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_44.getParent().(IfStmt).getThen()=target_86
}

predicate func_45(Variable vend_991, LogicalAndExpr target_44, ExprStmt target_45) {
		target_45.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vend_991
		and target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_46(Variable vcur_expr_991, Variable vend_991, Variable vj_992, LogicalAndExpr target_44, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_992
		and target_46.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_991
		and target_46.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vcur_expr_991
		and target_46.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_47(Variable vmodule_name_991, Variable vcur_expr_991, Variable vj_992, BlockStmt target_87, LogicalOrExpr target_47) {
		target_47.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vmodule_name_991
		and target_47.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_47.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcur_expr_991
		and target_47.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_name_991
		and target_47.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vj_992
		and target_47.getParent().(IfStmt).getThen()=target_87
}

predicate func_48(Variable vbuf_len_987, Variable vj_992, Variable vcount_992, BlockStmt target_88, RelationalOperation target_48) {
		 (target_48 instanceof GTExpr or target_48 instanceof LTExpr)
		and target_48.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_992
		and target_48.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_992
		and target_48.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_48.getParent().(IfStmt).getThen()=target_88
}

predicate func_49(Variable vexp_990, RelationalOperation target_48, ExprStmt target_49) {
		target_49.getExpr().(FunctionCall).getTarget().hasName("lyxp_expr_free")
		and target_49.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_990
		and target_49.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_48
}

predicate func_50(Variable vbuf_988, Variable vcur_expr_991, Variable vj_992, Variable vcount_992, LogicalOrExpr target_47, ExprStmt target_50) {
		target_50.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_50.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_988
		and target_50.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcount_992
		and target_50.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcur_expr_991
		and target_50.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vj_992
		and target_50.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_47
}

predicate func_51(Variable vj_992, Variable vcount_992, LogicalOrExpr target_47, ExprStmt target_51) {
		target_51.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcount_992
		and target_51.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vj_992
		and target_51.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_47
}

predicate func_52(Variable vmodule_name_991, Variable vcur_expr_991, LogicalAndExpr target_44, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmodule_name_991
		and target_52.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_expr_991
		and target_52.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_53(Variable vbuf_len_987, Variable vexp_990, Variable vi_992, Variable vj_992, Variable vcount_992, BlockStmt target_89, RelationalOperation target_53) {
		 (target_53 instanceof GTExpr or target_53 instanceof LTExpr)
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_992
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_53.getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vj_992
		and target_53.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_53.getParent().(IfStmt).getThen()=target_89
}

predicate func_54(Variable vexp_990, RelationalOperation target_53, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("lyxp_expr_free")
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_990
		and target_54.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
}

predicate func_55(Variable vbuf_988, Variable vexp_990, Variable vend_991, Variable vi_992, Variable vj_992, Variable vcount_992, LogicalAndExpr target_44, ExprStmt target_55) {
		target_55.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_55.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_988
		and target_55.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcount_992
		and target_55.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vend_991
		and target_55.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_55.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_55.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_55.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vj_992
		and target_55.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_56(Variable vexp_990, Variable vi_992, Variable vj_992, Variable vcount_992, LogicalAndExpr target_44, ExprStmt target_56) {
		target_56.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcount_992
		and target_56.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_56.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_56.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_56.getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vj_992
		and target_56.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_44
}

predicate func_57(Variable vbuf_len_987, Variable vexp_990, Variable vi_992, Variable vcount_992, BlockStmt target_90, RelationalOperation target_57) {
		 (target_57 instanceof GTExpr or target_57 instanceof LTExpr)
		and target_57.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_992
		and target_57.getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_57.getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_57.getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_57.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_57.getParent().(IfStmt).getThen()=target_90
}

predicate func_58(Variable vexp_990, RelationalOperation target_57, ExprStmt target_58) {
		target_58.getExpr().(FunctionCall).getTarget().hasName("lyxp_expr_free")
		and target_58.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_990
		and target_58.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
}

predicate func_59(Variable vbuf_len_987, Variable vcount_992, BlockStmt target_91, RelationalOperation target_59) {
		 (target_59 instanceof GTExpr or target_59 instanceof LTExpr)
		and target_59.getGreaterOperand().(VariableAccess).getTarget()=vcount_992
		and target_59.getLesserOperand().(VariableAccess).getTarget()=vbuf_len_987
		and target_59.getParent().(IfStmt).getThen()=target_91
}

predicate func_60(Variable vexp_990, RelationalOperation target_59, ExprStmt target_60) {
		target_60.getExpr().(FunctionCall).getTarget().hasName("lyxp_expr_free")
		and target_60.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_990
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_61(VariableAccess target_83, Function func, EmptyStmt target_61) {
		target_61.toString() = ";"
		and target_61.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_83
		and target_61.getEnclosingFunction() = func
}

predicate func_62(RelationalOperation target_40, Function func, EmptyStmt target_62) {
		target_62.toString() = ";"
		and target_62.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_40
		and target_62.getEnclosingFunction() = func
}

predicate func_63(RelationalOperation target_48, Function func, EmptyStmt target_63) {
		target_63.toString() = ";"
		and target_63.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_48
		and target_63.getEnclosingFunction() = func
}

predicate func_64(RelationalOperation target_53, Function func, EmptyStmt target_64) {
		target_64.toString() = ";"
		and target_64.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_64.getEnclosingFunction() = func
}

predicate func_65(RelationalOperation target_57, Function func, EmptyStmt target_65) {
		target_65.toString() = ";"
		and target_65.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
		and target_65.getEnclosingFunction() = func
}

predicate func_66(RelationalOperation target_59, Function func, EmptyStmt target_66) {
		target_66.toString() = ";"
		and target_66.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
		and target_66.getEnclosingFunction() = func
}

predicate func_70(Parameter vctx_985, ExprStmt target_70) {
		target_70.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_70.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_70.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_70.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_70.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_71(Parameter vctx_985, ExprStmt target_71) {
		target_71.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_71.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_71.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_71.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_71.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_71.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_72(Parameter vctx_985, ExprStmt target_72) {
		target_72.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_72.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_72.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_72.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_72.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_72.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_73(Parameter vctx_985, ExprStmt target_73) {
		target_73.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_73.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_73.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_73.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_73.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_74(Parameter vctx_985, ExprStmt target_74) {
		target_74.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_74.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_74.getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_74.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_74.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_74.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_75(Parameter vctx_985, BlockStmt target_75) {
		target_75.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_75.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_75.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_75.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_75.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_76(Variable vbuf_988, ExprStmt target_76) {
		target_76.getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_988
}

predicate func_77(Variable vbuf_988, Variable vcount_992, AddressOfExpr target_77) {
		target_77.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_988
		and target_77.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcount_992
}

predicate func_78(Variable vbits_989, Variable vi_992, ArrayExpr target_78) {
		target_78.getArrayBase().(VariableAccess).getTarget()=vbits_989
		and target_78.getArrayOffset().(VariableAccess).getTarget()=vi_992
}

predicate func_79(Variable vexp_990, Variable vi_992, ArrayExpr target_79) {
		target_79.getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_79.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_79.getArrayOffset().(VariableAccess).getTarget()=vi_992
}

predicate func_80(Parameter vctx_985, BlockStmt target_80) {
		target_80.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_80.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_80.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_80.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_80.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_81(Variable vexp_990, Variable vi_992, Variable vj_992, SubExpr target_81) {
		target_81.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tok_len"
		and target_81.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_990
		and target_81.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_992
		and target_81.getRightOperand().(VariableAccess).getTarget()=vj_992
}

predicate func_82(Parameter vctx_985, ExprStmt target_82) {
		target_82.getExpr().(FunctionCall).getTarget().hasName("lydict_remove")
		and target_82.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
}

predicate func_83(Parameter vtype_985, VariableAccess target_83) {
		target_83.getTarget()=vtype_985
}

predicate func_84(Parameter vctx_985, ExprStmt target_84) {
		target_84.getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_84.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_84.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_84.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_84.getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_85(Parameter vctx_985, BlockStmt target_85) {
		target_85.getStmt(0).(IfStmt).getCondition() instanceof RelationalOperation
		and target_85.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_85.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_85.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Internal error (%s:%d)."
		and target_85.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="/opt/project/build/cloned/libyang/src/parser.c"
		and target_85.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_86(BlockStmt target_86) {
		target_86.getStmt(0) instanceof ExprStmt
		and target_86.getStmt(1) instanceof ExprStmt
		and target_86.getStmt(2).(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_86.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof RelationalOperation
		and target_86.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_86.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof EmptyStmt
		and target_86.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_86.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr() instanceof Literal
}

predicate func_87(Parameter vctx_985, BlockStmt target_87) {
		target_87.getStmt(0).(IfStmt).getCondition() instanceof RelationalOperation
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_87.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_88(Parameter vctx_985, BlockStmt target_88) {
		target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_88.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_89(Parameter vctx_985, BlockStmt target_89) {
		target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_89.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_90(Parameter vctx_985, BlockStmt target_90) {
		target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_90.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_91(Parameter vctx_985, BlockStmt target_91) {
		target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_log")
		and target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_985
		and target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_91.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
}

from Function func, Parameter vctx_985, Parameter vtype_985, Variable vbuf_len_987, Variable vbuf_988, Variable vbits_989, Variable vexp_990, Variable vmodule_name_991, Variable vcur_expr_991, Variable vend_991, Variable vi_992, Variable vj_992, Variable vcount_992, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_7, Literal target_8, Literal target_12, Literal target_13, Literal target_17, Literal target_18, Literal target_20, NotExpr target_38, LogicalAndExpr target_39, RelationalOperation target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, LogicalAndExpr target_44, ExprStmt target_45, ExprStmt target_46, LogicalOrExpr target_47, RelationalOperation target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ExprStmt target_52, RelationalOperation target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56, RelationalOperation target_57, ExprStmt target_58, RelationalOperation target_59, ExprStmt target_60, EmptyStmt target_61, EmptyStmt target_62, EmptyStmt target_63, EmptyStmt target_64, EmptyStmt target_65, EmptyStmt target_66, ExprStmt target_70, ExprStmt target_71, ExprStmt target_72, ExprStmt target_73, ExprStmt target_74, BlockStmt target_75, ExprStmt target_76, AddressOfExpr target_77, ArrayExpr target_78, ArrayExpr target_79, BlockStmt target_80, SubExpr target_81, ExprStmt target_82, VariableAccess target_83, ExprStmt target_84, BlockStmt target_85, BlockStmt target_86, BlockStmt target_87, BlockStmt target_88, BlockStmt target_89, BlockStmt target_90, BlockStmt target_91
where
func_0(vctx_985, target_0)
and func_1(vctx_985, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_7(vctx_985, target_70, target_71, target_7)
and func_8(func, target_8)
and func_12(vctx_985, target_72, target_12)
and func_13(func, target_13)
and func_17(vctx_985, target_73, target_17)
and func_18(func, target_18)
and func_20(vctx_985, target_74, target_20)
and not func_21(vbuf_len_987, vbuf_988, vbits_989, vi_992, target_75, target_76, target_77, target_78)
and not func_22(vbits_989, vi_992, target_79, target_53)
and not func_23(func)
and not func_24(vbuf_len_987, vbits_989, vi_992, target_80, target_40, target_39, target_44)
and not func_25(vbits_989, vi_992, target_53, target_81)
and not func_26(func)
and not func_27(func)
and not func_29(func)
and not func_31(target_57, func)
and not func_32(func)
and not func_33(vctx_985, vend_991, target_59, target_73, target_82)
and not func_34(target_59, func)
and not func_35(func)
and not func_36(vctx_985, target_44, target_71, target_74)
and not func_37(vctx_985, target_83, target_84, target_72)
and func_38(vexp_990, target_75, target_38)
and func_39(vexp_990, vcur_expr_991, vend_991, vi_992, target_85, target_39)
and func_40(vbuf_len_987, vcur_expr_991, vend_991, vcount_992, target_80, target_40)
and func_41(vexp_990, target_40, target_41)
and func_42(vbuf_988, vcur_expr_991, vend_991, vcount_992, target_39, target_42)
and func_43(vcur_expr_991, vend_991, vcount_992, target_39, target_43)
and func_44(vexp_990, vcur_expr_991, vend_991, vi_992, target_86, target_44)
and func_45(vend_991, target_44, target_45)
and func_46(vcur_expr_991, vend_991, vj_992, target_44, target_46)
and func_47(vmodule_name_991, vcur_expr_991, vj_992, target_87, target_47)
and func_48(vbuf_len_987, vj_992, vcount_992, target_88, target_48)
and func_49(vexp_990, target_48, target_49)
and func_50(vbuf_988, vcur_expr_991, vj_992, vcount_992, target_47, target_50)
and func_51(vj_992, vcount_992, target_47, target_51)
and func_52(vmodule_name_991, vcur_expr_991, target_44, target_52)
and func_53(vbuf_len_987, vexp_990, vi_992, vj_992, vcount_992, target_89, target_53)
and func_54(vexp_990, target_53, target_54)
and func_55(vbuf_988, vexp_990, vend_991, vi_992, vj_992, vcount_992, target_44, target_55)
and func_56(vexp_990, vi_992, vj_992, vcount_992, target_44, target_56)
and func_57(vbuf_len_987, vexp_990, vi_992, vcount_992, target_90, target_57)
and func_58(vexp_990, target_57, target_58)
and func_59(vbuf_len_987, vcount_992, target_91, target_59)
and func_60(vexp_990, target_59, target_60)
and func_61(target_83, func, target_61)
and func_62(target_40, func, target_62)
and func_63(target_48, func, target_63)
and func_64(target_53, func, target_64)
and func_65(target_57, func, target_65)
and func_66(target_59, func, target_66)
and func_70(vctx_985, target_70)
and func_71(vctx_985, target_71)
and func_72(vctx_985, target_72)
and func_73(vctx_985, target_73)
and func_74(vctx_985, target_74)
and func_75(vctx_985, target_75)
and func_76(vbuf_988, target_76)
and func_77(vbuf_988, vcount_992, target_77)
and func_78(vbits_989, vi_992, target_78)
and func_79(vexp_990, vi_992, target_79)
and func_80(vctx_985, target_80)
and func_81(vexp_990, vi_992, vj_992, target_81)
and func_82(vctx_985, target_82)
and func_83(vtype_985, target_83)
and func_84(vctx_985, target_84)
and func_85(vctx_985, target_85)
and func_86(target_86)
and func_87(vctx_985, target_87)
and func_88(vctx_985, target_88)
and func_89(vctx_985, target_89)
and func_90(vctx_985, target_90)
and func_91(vctx_985, target_91)
and vctx_985.getType().hasName("ly_ctx *")
and vtype_985.getType().hasName("int")
and vbuf_len_987.getType().hasName("const uint16_t")
and vbuf_988.getType().hasName("char[512]")
and vbits_989.getType().hasName("lys_type_bit **")
and vexp_990.getType().hasName("lyxp_expr *")
and vmodule_name_991.getType().hasName("const char *")
and vcur_expr_991.getType().hasName("const char *")
and vend_991.getType().hasName("const char *")
and vi_992.getType().hasName("int")
and vj_992.getType().hasName("int")
and vcount_992.getType().hasName("int")
and vctx_985.getParentScope+() = func
and vtype_985.getParentScope+() = func
and vbuf_len_987.getParentScope+() = func
and vbuf_988.getParentScope+() = func
and vbits_989.getParentScope+() = func
and vexp_990.getParentScope+() = func
and vmodule_name_991.getParentScope+() = func
and vcur_expr_991.getParentScope+() = func
and vend_991.getParentScope+() = func
and vi_992.getParentScope+() = func
and vj_992.getParentScope+() = func
and vcount_992.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
