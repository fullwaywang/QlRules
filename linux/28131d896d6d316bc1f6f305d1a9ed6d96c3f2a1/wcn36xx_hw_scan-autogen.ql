/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_hw_scan
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-hw-scan
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_hw_scan CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand() instanceof ValueFieldAccess
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="48"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printk")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="4wcn36xx: WARNING Offload scan aborted, n_channels=%u"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="n_channels"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_7(Parameter vhw_req_659, Variable vwcn_661, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("wcn36xx_smd_update_channel_list")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwcn_661
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="req"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhw_req_659
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_7))
}

predicate func_8(Parameter vhw_req_659) {
	exists(ValueFieldAccess target_8 |
		target_8.getTarget().getName()="n_channels"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhw_req_659)
}

predicate func_9(Parameter vhw_req_659) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="req"
		and target_9.getQualifier().(VariableAccess).getTarget()=vhw_req_659)
}

predicate func_10(Function func) {
	exists(ReturnStmt target_10 |
		target_10.getExpr().(Literal).getValue()="1"
		and target_10.getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="0"
		and target_11.getEnclosingFunction() = func)
}

predicate func_13(Variable vi_662, Function func) {
	exists(ForStmt target_13 |
		target_13.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_662
		and target_13.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_13.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_662
		and target_13.getCondition().(RelationalOperation).getGreaterOperand() instanceof ValueFieldAccess
		and target_13.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_662
		and target_13.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="band"
		and target_13.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="channels"
		and target_13.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_13.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_662
		and target_13.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen() instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_17(Variable vwcn_661) {
	exists(PointerFieldAccess target_17 |
		target_17.getTarget().getName()="scan_aborted"
		and target_17.getQualifier().(VariableAccess).getTarget()=vwcn_661)
}

from Function func, Parameter vhw_req_659, Variable vwcn_661, Variable vi_662
where
not func_0(func)
and not func_7(vhw_req_659, vwcn_661, func)
and func_8(vhw_req_659)
and func_9(vhw_req_659)
and func_10(func)
and func_11(func)
and func_13(vi_662, func)
and vhw_req_659.getType().hasName("ieee80211_scan_request *")
and vwcn_661.getType().hasName("wcn36xx *")
and func_17(vwcn_661)
and vhw_req_659.getParentScope+() = func
and vwcn_661.getParentScope+() = func
and vi_662.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
