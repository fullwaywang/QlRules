/**
 * @name ffmpeg-6f53f0d09ea4c9c7f7354f018a87ef840315207d-build_open_gop_key_points
 * @id cpp/ffmpeg/6f53f0d09ea4c9c7f7354f018a87ef840315207d/build-open-gop-key-points
 * @description ffmpeg-6f53f0d09ea4c9c7f7354f018a87ef840315207d-libavformat/mov.c-build_open_gop_key_points CVE-2022-2566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsc_3945, Variable vi_3979, RelationalOperation target_8, AddressOfExpr target_9, PostfixIncrExpr target_10) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ctts_data"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3979
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sample_offsets_count"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsc_3945, Variable vi_3971, EqualityOperation target_11, ArrayExpr target_12, ExprStmt target_7, ArrayExpr target_13) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3971
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="open_key_samples_count"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_13.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsample_id_3943, ExprStmt target_14) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const MOVSbgp *")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsample_id_3943
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1163346256"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Variable vk_3942, Variable vsample_id_3943, Variable vcra_index_3944, Variable vsc_3945, Variable vsg_3980, Variable vj_3982, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="index"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsg_3980
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcra_index_3944
		and target_4.getThen().(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_3982
		and target_4.getThen().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_4.getThen().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsg_3980
		and target_4.getThen().(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_3982
		and target_4.getThen().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="open_key_samples"
		and target_4.getThen().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_4.getThen().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vk_3942
		and target_4.getThen().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsample_id_3943
}

predicate func_5(Variable vsample_id_3943, Variable vsg_3980, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsample_id_3943
		and target_5.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="count"
		and target_5.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsg_3980
}

predicate func_6(Variable vsc_3945, Variable vi_3952, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sample_offsets_count"
		and target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_6.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="count"
		and target_6.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ctts_data"
		and target_6.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_6.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3952
}

predicate func_7(Variable vsc_3945, Variable vi_3971, EqualityOperation target_11, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="open_key_samples_count"
		and target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_7.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="count"
		and target_7.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_7.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_7.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3971
		and target_7.getParent().(IfStmt).getCondition()=target_11
}

predicate func_8(Variable vsc_3945, Variable vi_3979, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vi_3979
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="sync_group_count"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
}

predicate func_9(Variable vsc_3945, Variable vi_3979, AddressOfExpr target_9) {
		target_9.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_9.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_9.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3979
}

predicate func_10(Variable vi_3979, PostfixIncrExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vi_3979
}

predicate func_11(Variable vcra_index_3944, Variable vsc_3945, Variable vi_3971, EqualityOperation target_11) {
		target_11.getAnOperand().(ValueFieldAccess).getTarget().getName()="index"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3971
		and target_11.getAnOperand().(VariableAccess).getTarget()=vcra_index_3944
}

predicate func_12(Variable vsc_3945, Variable vi_3971, ArrayExpr target_12) {
		target_12.getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_12.getArrayOffset().(VariableAccess).getTarget()=vi_3971
}

predicate func_13(Variable vsc_3945, Variable vi_3971, ArrayExpr target_13) {
		target_13.getArrayBase().(PointerFieldAccess).getTarget().getName()="sync_group"
		and target_13.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_13.getArrayOffset().(VariableAccess).getTarget()=vi_3971
}

predicate func_14(Variable vk_3942, Variable vsample_id_3943, Variable vsc_3945, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="open_key_samples"
		and target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_3945
		and target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vk_3942
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsample_id_3943
}

from Function func, Variable vk_3942, Variable vsample_id_3943, Variable vcra_index_3944, Variable vsc_3945, Variable vi_3952, Variable vi_3971, Variable vi_3979, Variable vsg_3980, Variable vj_3982, IfStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, AddressOfExpr target_9, PostfixIncrExpr target_10, EqualityOperation target_11, ArrayExpr target_12, ArrayExpr target_13, ExprStmt target_14
where
not func_0(vsc_3945, vi_3979, target_8, target_9, target_10)
and not func_1(vsc_3945, vi_3971, target_11, target_12, target_7, target_13)
and not func_2(vsample_id_3943, target_14)
and func_4(vk_3942, vsample_id_3943, vcra_index_3944, vsc_3945, vsg_3980, vj_3982, target_4)
and func_5(vsample_id_3943, vsg_3980, target_5)
and func_6(vsc_3945, vi_3952, target_6)
and func_7(vsc_3945, vi_3971, target_11, target_7)
and func_8(vsc_3945, vi_3979, target_8)
and func_9(vsc_3945, vi_3979, target_9)
and func_10(vi_3979, target_10)
and func_11(vcra_index_3944, vsc_3945, vi_3971, target_11)
and func_12(vsc_3945, vi_3971, target_12)
and func_13(vsc_3945, vi_3971, target_13)
and func_14(vk_3942, vsample_id_3943, vsc_3945, target_14)
and vk_3942.getType().hasName("int")
and vsample_id_3943.getType().hasName("int")
and vcra_index_3944.getType().hasName("uint32_t")
and vsc_3945.getType().hasName("MOVStreamContext *")
and vi_3952.getType().hasName("uint32_t")
and vi_3971.getType().hasName("uint32_t")
and vi_3979.getType().hasName("uint32_t")
and vsg_3980.getType().hasName("const MOVSbgp *")
and vj_3982.getType().hasName("uint32_t")
and vk_3942.getParentScope+() = func
and vsample_id_3943.getParentScope+() = func
and vcra_index_3944.getParentScope+() = func
and vsc_3945.getParentScope+() = func
and vi_3952.getParentScope+() = func
and vi_3971.getParentScope+() = func
and vi_3979.getParentScope+() = func
and vsg_3980.getParentScope+() = func
and vj_3982.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
