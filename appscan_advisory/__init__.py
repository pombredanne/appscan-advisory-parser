from lxml import etree

class AppscanAdvisory():
    id = ''
    name = ''
    description = ''
    classification = {
        'name': '',
        'reference': '',
    }
    technical_description = ''
    causes = []
    risks = []
    affected_products = []
    xfid = ''
    references = []
    recommendations = []

    def __init__(self, file, contents):
        self.id = file.split('/')[-1].rstrip('.xml')
        try:
            advisory_root = etree.XML(contents)
            if advisory_root.find('name') is not None:
                self.name = advisory_root.find('name').text

            if advisory_root.find('testDescription') is not None:
                self.description = advisory_root.find('testDescription').text

            if (advisory_root.find('threatClassification/name') is not None and advisory_root.find('threatClassification/reference') is not None):
                self.classification.update({
                    'name': advisory_root.find('threatClassification/name').text,
                    'reference': advisory_root.find('threatClassification/reference').text,
                })

            if advisory_root.find('testTechnicalDescription') is not None:
                self.technical_description = advisory_root.find('testTechnicalDescription')

            for cause in advisory_root.find('causes'):
                if cause.text not in self.causes:
                    self.causes.append(cause.text)
            for risk in advisory_root.find('securityRisks'):
                if risk.text not in self.risks:
                    self.risks.append(risk.text)
            for affected_product in advisory_root.find('affectedProducts'):
                if affected_product.text not in self.affected_products:
                    self.affected_products.append(affected_product.text)

            if advisory_root.find('xfid/link') is not None:
                self.xfid = advisory_root.find('xfid/link').get('target')

            for reference in advisory_root.find('references').iterchildren():
                if len([ref for ref in self.references if ref['url'] == reference.get('target') and ref['name'] == reference.text]) == 0:
                    self.references.append({
                        'name': reference.text,
                        'url': reference.get('target'),
                    })

            for recommendation in advisory_root.find('fixRecommendations'):
                type = recommendation.get('type')
                description = self._build_text(recommendation)
                if len([rec for rec in self.recommendations if rec['type'] == type and rec['description'] == description]) == 0:
                    self.recommendations.append({
                        'type': recommendation.get('type'),
                        'description': self._build_text(recommendation),
                    })

        except Exception as e:
            print '[-] AppscanAdvisory() - Failure parsing XML contents'
            print '[-] File: %s' % file
            print '[-]    *%s' % e

    def _build_text(self, element):
        output = ''
        for children in element.iterchildren():
            if not children.text:
                output += '\n\n'
                continue
            output += '%s\n' % children.text
        return output

    def _todict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'classification': self.classification,
            'technical_description': self.technical_description,
            'causes': self.causes,
            'risks': self.risks,
            'affected_products': self.affected_products,
            'references': self.references,
            'recommendations': self.recommendations,
            'xfid': self.xfid,
        }
