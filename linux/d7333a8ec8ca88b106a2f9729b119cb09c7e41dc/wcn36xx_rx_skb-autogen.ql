/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_rx_skb
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-rx-skb
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_rx_skb CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbd_232, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="mpdu_data_off"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="mpdu_header_off"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="mpdu_len"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="mpdu_header_len"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vskb_227, Variable vbd_232, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="asf"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="esf"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_data_off"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_len"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3872"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("skb_put")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_227
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_data_off"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_len"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("skb_pull")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_227
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="mpdu_data_off"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_1.getThen().(BlockStmt).getStmt(3).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1))
}

predicate func_6(Variable vbd_232, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="mpdu_header_off"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="76"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbd_232
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_header_off"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="mpdu_len"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="3872"
		and target_6.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_6))
}

predicate func_7(Variable vstatus_229, Variable vbd_232, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(PointerFieldAccess).getTarget().getName()="scan_learn"
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_7.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="reserved0"
		and target_7.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_7.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_7.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rx_ch"
		and target_7.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rf_band"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("u8")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("const u8[25]")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("u8")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="band"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="freq"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ieee80211_channel_to_frequency")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const u8[25]")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("u8")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="band"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="band"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="freq"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ieee80211_channel_to_frequency")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("u8")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="band"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_229
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_7))
}

predicate func_14(Function func) {
	exists(LabelStmt target_14 |
		target_14.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_14))
}

predicate func_15(Parameter vwcn_227, Parameter vskb_227, Variable vbd_232, Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="asf"
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lsf"
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="esf"
		and target_15.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_15.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="esf"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("skb_queue_empty")
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_227
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printk")
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3wcn36xx: ERROR Discarding non complete chain"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__skb_queue_purge_irq")
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_15.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_227
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__skb_queue_tail")
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_227
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vskb_227
		and target_15.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lsf"
		and target_15.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_15.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen() instanceof ReturnStmt
		and target_15.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vskb_227
		and target_15.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wcn36xx_unchain_msdu")
		and target_15.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_15.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_227
		and target_15.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vskb_227
		and target_15.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_15))
}

predicate func_28(Function func) {
	exists(ReturnStmt target_28 |
		target_28.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_28 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_28))
}

predicate func_30(Parameter vskb_227, Variable vbd_232, Function func) {
	exists(ExprStmt target_30 |
		target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printk")
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3wcn36xx: ERROR Drop frame! skb:%p len:%u hoff:%u doff:%u asf=%u esf=%u lsf=%u\n"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vskb_227
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mpdu_len"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="mpdu_header_off"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="mpdu_data_off"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="asf"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="esf"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="lsf"
		and target_30.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_232
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_30 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_30))
}

predicate func_36(Parameter vskb_227, Function func) {
	exists(ExprStmt target_36 |
		target_36.getExpr().(FunctionCall).getTarget().hasName("dev_kfree_skb_irq")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_227
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_36 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_36))
}

predicate func_38(Function func) {
	exists(ReturnStmt target_38 |
		target_38.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_38.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_38 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_38))
}

predicate func_40(Parameter vwcn_227) {
	exists(PointerFieldAccess target_40 |
		target_40.getTarget().getName()="hw"
		and target_40.getQualifier().(VariableAccess).getTarget()=vwcn_227)
}

predicate func_42(Parameter vskb_227) {
	exists(PointerFieldAccess target_42 |
		target_42.getTarget().getName()="data"
		and target_42.getQualifier().(VariableAccess).getTarget()=vskb_227)
}

predicate func_43(Parameter vskb_227) {
	exists(PointerFieldAccess target_43 |
		target_43.getTarget().getName()="len"
		and target_43.getQualifier().(VariableAccess).getTarget()=vskb_227)
}

predicate func_44(Parameter vwcn_227, Parameter vskb_227) {
	exists(FunctionCall target_44 |
		target_44.getTarget().hasName("ieee80211_rx_irqsafe")
		and target_44.getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_44.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_227
		and target_44.getArgument(1).(VariableAccess).getTarget()=vskb_227)
}

predicate func_45(Variable vbd_232) {
	exists(FunctionCall target_45 |
		target_45.getTarget().hasName("print_hex_dump")
		and target_45.getArgument(0).(StringLiteral).getValue()="7"
		and target_45.getArgument(1).(StringLiteral).getValue()="wcn36xx: BD   <<< "
		and target_45.getArgument(3).(Literal).getValue()="32"
		and target_45.getArgument(4).(Literal).getValue()="1"
		and target_45.getArgument(5).(VariableAccess).getTarget()=vbd_232
		and target_45.getArgument(6).(SizeofTypeOperator).getType() instanceof LongType
		and target_45.getArgument(6).(SizeofTypeOperator).getValue()="76")
}

predicate func_46(Variable vbd_232) {
	exists(PointerFieldAccess target_46 |
		target_46.getTarget().getName()="rate_id"
		and target_46.getQualifier().(VariableAccess).getTarget()=vbd_232)
}

from Function func, Parameter vwcn_227, Parameter vskb_227, Variable vstatus_229, Variable vbd_232
where
not func_0(vbd_232, func)
and not func_1(vskb_227, vbd_232, func)
and not func_6(vbd_232, func)
and not func_7(vstatus_229, vbd_232, func)
and not func_14(func)
and not func_15(vwcn_227, vskb_227, vbd_232, func)
and not func_28(func)
and not func_30(vskb_227, vbd_232, func)
and not func_36(vskb_227, func)
and not func_38(func)
and vwcn_227.getType().hasName("wcn36xx *")
and func_40(vwcn_227)
and vskb_227.getType().hasName("sk_buff *")
and func_42(vskb_227)
and func_43(vskb_227)
and func_44(vwcn_227, vskb_227)
and vstatus_229.getType().hasName("ieee80211_rx_status")
and vbd_232.getType().hasName("wcn36xx_rx_bd *")
and func_45(vbd_232)
and func_46(vbd_232)
and vwcn_227.getParentScope+() = func
and vskb_227.getParentScope+() = func
and vstatus_229.getParentScope+() = func
and vbd_232.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
