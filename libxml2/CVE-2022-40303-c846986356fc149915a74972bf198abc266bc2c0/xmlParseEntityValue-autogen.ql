/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseEntityValue
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseEntityValue
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseEntityValue CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_3757, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3757
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(Literal).getValue()="10000000"
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_0)
}

predicate func_1(Parameter vctxt_3757, Variable vlen_3759) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3759
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3757
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="entity value too long\n"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

predicate func_4(Parameter vctxt_3757, Variable vl_3761) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("xmlCurrentChar")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vctxt_3757
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3761)
}

predicate func_5(Variable vbuf_3758, Variable vlen_3759) {
	exists(ArrayExpr target_5 |
		target_5.getArrayBase().(VariableAccess).getTarget()=vbuf_3758
		and target_5.getArrayOffset().(VariableAccess).getTarget()=vlen_3759)
}

from Function func, Parameter vctxt_3757, Variable vbuf_3758, Variable vlen_3759, Variable vl_3761
where
not func_0(vctxt_3757, func)
and not func_1(vctxt_3757, vlen_3759)
and vctxt_3757.getType().hasName("xmlParserCtxtPtr")
and func_4(vctxt_3757, vl_3761)
and vlen_3759.getType().hasName("int")
and func_5(vbuf_3758, vlen_3759)
and vl_3761.getType().hasName("int")
and vctxt_3757.getParentScope+() = func
and vbuf_3758.getParentScope+() = func
and vlen_3759.getParentScope+() = func
and vl_3761.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
